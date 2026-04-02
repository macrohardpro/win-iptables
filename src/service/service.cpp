// service.cpp — Windows service entry point
//
// WiniptablesService wraps the service state machine:
//   ServiceMain  — service main function called by SCM
//   HandlerEx    — control handler function called by SCM
//   Start()      — service startup logic
//   Stop()       — service shutdown logic

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "service.hpp"

#include "winiptables/imatch.hpp"  // full IMatch definition (needed for Rule destructor)
#include "winiptables/log.hpp"

#include <cstdio>
#include <string>

namespace winiptables {

// -----------------------------------------------------------------------
// Global singleton
// -----------------------------------------------------------------------
WiniptablesService* WiniptablesService::instance_ = nullptr;

// -----------------------------------------------------------------------
// Persistence path helpers
// -----------------------------------------------------------------------

std::string GetPersistPath() {
    char buf[MAX_PATH] = {};
    DWORD len = GetEnvironmentVariableA("ProgramData", buf, MAX_PATH);
    std::string base = (len > 0) ? std::string(buf) : "C:\\ProgramData";
    return base + "\\winiptables\\rules.v4";
}

void EnsurePersistDir() {
    char buf[MAX_PATH] = {};
    DWORD len = GetEnvironmentVariableA("ProgramData", buf, MAX_PATH);
    std::string dir = (len > 0) ? std::string(buf) : "C:\\ProgramData";
    dir += "\\winiptables";
    CreateDirectoryA(dir.c_str(), nullptr);  // Ignore ERROR_ALREADY_EXISTS when the directory already exists
}

// -----------------------------------------------------------------------
// Ctor / dtor
// -----------------------------------------------------------------------

WiniptablesService::WiniptablesService() {
    instance_ = this;
    stop_event_ = CreateEventA(nullptr, TRUE, FALSE, nullptr);

    // Initialize SERVICE_STATUS structure
    status_.dwServiceType             = SERVICE_WIN32_OWN_PROCESS;
    status_.dwCurrentState            = SERVICE_STOPPED;
    status_.dwControlsAccepted        = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    status_.dwWin32ExitCode           = NO_ERROR;
    status_.dwServiceSpecificExitCode = 0;
    status_.dwCheckPoint              = 0;
    status_.dwWaitHint                = 0;
}

WiniptablesService::~WiniptablesService() {
    if (stop_event_ != INVALID_HANDLE_VALUE) {
        CloseHandle(stop_event_);
        stop_event_ = INVALID_HANDLE_VALUE;
    }
    instance_ = nullptr;
}

// -----------------------------------------------------------------------
// Task 14.2: service startup logic
// -----------------------------------------------------------------------

bool WiniptablesService::Start() {
    LOG_INFO("Service starting...");

    // 1. Initialize RuleStore (constructor sets up built-in tables/chains)
    store_ = std::make_unique<RuleStore>();
    LOG_DEBUG("RuleStore initialized");

    // 2. Load rules from the persistence file (skip if it doesn't exist)
    std::string persist_path = GetPersistPath();
    {
        DWORD attr = GetFileAttributesA(persist_path.c_str());
        if (attr != INVALID_FILE_ATTRIBUTES) {
            LOG_INFO("Loading rules from {}", persist_path);
            if (!RulePersist::load(*store_, persist_path)) {
                LOG_ERROR("Failed to load rules from {}", persist_path);
                fprintf(stderr, "[winiptables] Warning: failed to load rules from %s\n",
                        persist_path.c_str());
            } else {
                LOG_INFO("Rules loaded successfully from {}", persist_path);
            }
        } else {
            LOG_INFO("No persist file found at {}, starting with empty ruleset", persist_path);
        }
    }

    // 3. Initialize StatefulTracker
    tracker_ = std::make_unique<StatefulTracker>();
    LOG_DEBUG("StatefulTracker initialized");

    // 4. Initialize TablePipeline (holds a RuleStore reference)
    pipeline_ = std::make_unique<TablePipeline>(*store_);
    LOG_DEBUG("TablePipeline initialized");

    // 5. Open WinDivert handle
    auto capture_opt = PacketCapture::Open("ip or ipv6");
    if (!capture_opt.has_value()) {
        LOG_ERROR("Failed to open WinDivert handle — ensure the service is running as Administrator");
        fprintf(stderr, "[winiptables] Error: failed to open WinDivert handle\n");
        return false;
    }
    capture_ = std::make_unique<PacketCapture>(std::move(*capture_opt));
    LOG_INFO("WinDivert handle opened");

    // 6. Start PacketCapture thread pool (4 worker threads)
    capture_->Start(4, pipeline_.get(), store_.get());
    LOG_INFO("PacketCapture started with 4 worker threads");

    // 7. Initialize CommandDispatcher (holds a RuleStore reference)
    dispatcher_ = std::make_unique<CommandDispatcher>(*store_);
    LOG_DEBUG("CommandDispatcher initialized");

    // 8. Start IpcServer (register CommandDispatcher::dispatch as handler)
    ipc_server_ = std::make_unique<IpcServer>(
        [this](const std::vector<std::string>& argv,
               std::string& stdout_out,
               std::string& stderr_out) -> int {
            return dispatcher_->dispatch(argv, stdout_out, stderr_out);
        });
    ipc_server_->Start();
    LOG_INFO("IPC server started");

    LOG_INFO("Service started successfully");
    return true;
}

// -----------------------------------------------------------------------
// Helper: stop the WinDivert kernel driver via SCM
// Called after all WinDivert handles are closed so the driver can unload.
// -----------------------------------------------------------------------

static void StopWinDivertDriver() {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        LOG_ERROR("StopWinDivertDriver: OpenSCManager failed: {}", GetLastError());
        return;
    }

    // WinDivert registers its driver service as "WinDivert" (version-suffixed in
    // newer releases, e.g. "WinDivert14"). Try both names.
    const char* kNames[] = {"WinDivert", "WinDivert14"};
    SC_HANDLE svc = nullptr;
    for (const char* name : kNames) {
        svc = OpenServiceA(scm, name, SERVICE_STOP | SERVICE_QUERY_STATUS);
        if (svc) {
            LOG_DEBUG("StopWinDivertDriver: found service '{}'", name);
            break;
        }
    }

    if (!svc) {
        // Driver not found — already unloaded or never loaded
        LOG_DEBUG("StopWinDivertDriver: WinDivert service not found, nothing to stop");
        CloseServiceHandle(scm);
        return;
    }

    SERVICE_STATUS ss{};
    if (QueryServiceStatus(svc, &ss) && ss.dwCurrentState == SERVICE_STOPPED) {
        LOG_DEBUG("StopWinDivertDriver: driver already stopped");
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return;
    }

    SERVICE_STATUS stop_status{};
    if (!ControlService(svc, SERVICE_CONTROL_STOP, &stop_status)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_NOT_ACTIVE) {
            LOG_ERROR("StopWinDivertDriver: ControlService(STOP) failed: {}", err);
        }
    } else {
        // Wait up to 3 seconds for the driver to stop
        for (int i = 0; i < 6; ++i) {
            Sleep(500);
            if (QueryServiceStatus(svc, &ss) &&
                ss.dwCurrentState == SERVICE_STOPPED) {
                LOG_INFO("WinDivert driver stopped successfully");
                break;
            }
        }
        if (ss.dwCurrentState != SERVICE_STOPPED) {
            LOG_WARN("WinDivert driver did not stop within timeout");
        }
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
}


void WiniptablesService::Stop() {
    LOG_INFO("Service stopping...");

    // 1. Stop packet processing
    if (capture_) {
        capture_->Stop();
        LOG_INFO("PacketCapture stopped");
    }

    // 2. Save rules to persistence file
    if (store_) {
        EnsurePersistDir();
        std::string persist_path = GetPersistPath();
        LOG_INFO("Saving rules to {}", persist_path);
        if (!RulePersist::save(*store_, persist_path)) {
            LOG_ERROR("Failed to save rules to {}", persist_path);
            fprintf(stderr, "[winiptables] Warning: failed to save rules to %s\n",
                    persist_path.c_str());
        } else {
            LOG_INFO("Rules saved successfully to {}", persist_path);
        }
    }

    // 3. Stop IPC server
    if (ipc_server_) {
        ipc_server_->Stop();
        LOG_INFO("IPC server stopped");
    }

    // Release resources in reverse order
    ipc_server_.reset();
    dispatcher_.reset();
    capture_.reset();   // closes WinDivert handle — must happen before StopWinDivertDriver()
    pipeline_.reset();
    tracker_.reset();
    store_.reset();

    // Stop the WinDivert kernel driver now that all handles are closed
    StopWinDivertDriver();

    LOG_INFO("Service stopped");
}

// -----------------------------------------------------------------------
// SCM status reporting
// -----------------------------------------------------------------------

void WiniptablesService::ReportStatus(DWORD state, DWORD exit_code,
                                       DWORD wait_hint) {
    static DWORD check_point = 1;

    status_.dwCurrentState  = state;
    status_.dwWin32ExitCode = exit_code;
    status_.dwWaitHint      = wait_hint;

    if (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING) {
        status_.dwControlsAccepted = 0;
        status_.dwCheckPoint       = check_point++;
    } else {
        status_.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
        status_.dwCheckPoint       = 0;
    }

    if (status_handle_) {
        SetServiceStatus(status_handle_, &status_);
    }
}

// -----------------------------------------------------------------------
// Task 14.1: ServiceMain — service entry called by SCM
// -----------------------------------------------------------------------

VOID WINAPI WiniptablesService::ServiceMain(DWORD /*argc*/, LPSTR* /*argv*/) {
    WiniptablesService* svc = instance_;
    if (!svc) return;

    // Register control handler
    svc->status_handle_ = RegisterServiceCtrlHandlerExA(
        "winiptables",
        WiniptablesService::HandlerEx,
        svc  // context pointer
    );
    if (!svc->status_handle_) return;

    // Report SERVICE_START_PENDING
    svc->ReportStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

    // Run startup logic
    if (!svc->Start()) {
        LOG_ERROR("Service failed to start");
        svc->ReportStatus(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR);
        return;
    }

    // Report SERVICE_RUNNING
    svc->ReportStatus(SERVICE_RUNNING);
    LOG_INFO("Service is running");

    // Wait for stop signal
    WaitForSingleObject(svc->stop_event_, INFINITE);

    // Report SERVICE_STOP_PENDING
    svc->ReportStatus(SERVICE_STOP_PENDING, NO_ERROR, 5000);

    // Run shutdown logic
    svc->Stop();

    // Report SERVICE_STOPPED
    svc->ReportStatus(SERVICE_STOPPED);
}

// -----------------------------------------------------------------------
// Task 14.1: HandlerEx — control handler called by SCM
// -----------------------------------------------------------------------

DWORD WINAPI WiniptablesService::HandlerEx(DWORD control,
                                            DWORD /*event_type*/,
                                            LPVOID /*event_data*/,
                                            LPVOID context) {
    WiniptablesService* svc = static_cast<WiniptablesService*>(context);
    if (!svc) return ERROR_CALL_NOT_IMPLEMENTED;

    switch (control) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            LOG_INFO("Received stop/shutdown control signal");
            svc->ReportStatus(SERVICE_STOP_PENDING, NO_ERROR, 5000);
            SetEvent(svc->stop_event_);
            return NO_ERROR;

        case SERVICE_CONTROL_PAUSE:
            // Pause: stop packet capture but keep IPC server running
            LOG_INFO("Service paused");
            if (svc->capture_) svc->capture_->Stop();
            svc->ReportStatus(SERVICE_PAUSED);
            return NO_ERROR;

        case SERVICE_CONTROL_CONTINUE:
            // Continue: restart packet capture
            LOG_INFO("Service resumed");
            if (svc->capture_ && svc->pipeline_ && svc->store_) {
                svc->capture_->Start(4, svc->pipeline_.get(), svc->store_.get());
            }
            svc->ReportStatus(SERVICE_RUNNING);
            return NO_ERROR;

        case SERVICE_CONTROL_INTERROGATE:
            // SCM queries current status
            SetServiceStatus(svc->status_handle_, &svc->status_);
            return NO_ERROR;

        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

// -----------------------------------------------------------------------
// Task 14.2: RunAsService — run in service mode
// -----------------------------------------------------------------------

int WiniptablesService::RunAsService() {
    SERVICE_TABLE_ENTRYA dispatch_table[] = {
        { const_cast<LPSTR>("winiptables"), WiniptablesService::ServiceMain },
        { nullptr, nullptr }
    };

    if (!StartServiceCtrlDispatcherA(dispatch_table)) {
        DWORD err = GetLastError();
        if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            LOG_ERROR("Not running as a Windows service; use --console for console mode");
            fprintf(stderr,
                "[winiptables] Not running as a Windows service. "
                "Use --console for console mode.\n");
        } else {
            LOG_ERROR("StartServiceCtrlDispatcher failed: {}", err);
            fprintf(stderr,
                "[winiptables] StartServiceCtrlDispatcher failed: %lu\n", err);
        }
        return 1;
    }
    return 0;
}

// -----------------------------------------------------------------------
// Console mode: Ctrl+C handler
// -----------------------------------------------------------------------

static WiniptablesService* g_console_svc = nullptr;

static BOOL WINAPI ConsoleCtrlHandler(DWORD ctrl_type) {
    if (ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_BREAK_EVENT ||
        ctrl_type == CTRL_CLOSE_EVENT) {
        if (g_console_svc) {
            LOG_INFO("Console stop signal received");
            fprintf(stdout, "\n[winiptables] Stopping...\n");
            g_console_svc->Stop();
            SetEvent(g_console_svc->stop_event_);
        }
        return TRUE;
    }
    return FALSE;
}

int WiniptablesService::RunAsConsole() {
    g_console_svc = this;
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    fprintf(stdout, "[winiptables] Starting in console mode...\n");

    if (!Start()) {
        LOG_ERROR("Failed to start service in console mode");
        fprintf(stderr, "[winiptables] Failed to start service.\n");
        return 1;
    }

    fprintf(stdout, "[winiptables] Running. Press Ctrl+C to stop.\n");

    // Wait for stop signal
    WaitForSingleObject(stop_event_, INFINITE);

    fprintf(stdout, "[winiptables] Stopped.\n");
    SetConsoleCtrlHandler(ConsoleCtrlHandler, FALSE);
    g_console_svc = nullptr;
    return 0;
}

// -----------------------------------------------------------------------
// Task 14.5: service install / uninstall
// -----------------------------------------------------------------------

int WiniptablesService::Install() {
    // Get current executable path
    char exe_path[MAX_PATH] = {};
    if (!GetModuleFileNameA(nullptr, exe_path, MAX_PATH)) {
        fprintf(stderr, "[winiptables] GetModuleFileName failed: %lu\n",
                GetLastError());
        return 1;
    }

    // Open SCM
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            fprintf(stderr,
                "[winiptables] Access denied. Please run as Administrator.\n");
        } else {
            fprintf(stderr, "[winiptables] OpenSCManager failed: %lu\n", err);
        }
        return 1;
    }

    // Build service binary path (with "service" argument to run in service mode)
    std::string bin_path = std::string("\"") + exe_path + "\" service";

    // Create service
    SC_HANDLE svc = CreateServiceA(
        scm,
        "winiptables",                          // service name
        "winiptables Packet Filter Service",    // display name
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,              // service type
        SERVICE_AUTO_START,                     // start type: automatic
        SERVICE_ERROR_NORMAL,
        bin_path.c_str(),                       // binary path
        nullptr,                                // no load ordering group
        nullptr,                                // no tag ID
        nullptr,                                // no dependencies
        nullptr,                                // LocalSystem account
        nullptr                                 // no password
    );

    if (!svc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            fprintf(stderr, "[winiptables] Service already installed.\n");
        } else {
            fprintf(stderr, "[winiptables] CreateService failed: %lu\n", err);
        }
        CloseServiceHandle(scm);
        return 1;
    }

    // Set service description
    SERVICE_DESCRIPTIONA desc{};
    desc.lpDescription = const_cast<LPSTR>(
        "winiptables Windows packet filter service. "
        "Provides iptables-compatible firewall rules via WinDivert.");
    ChangeServiceConfig2A(svc, SERVICE_CONFIG_DESCRIPTION, &desc);

    fprintf(stdout, "[winiptables] Service installed successfully.\n");
    fprintf(stdout, "[winiptables] Use 'sc start winiptables' to start the service.\n");

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

int WiniptablesService::Uninstall() {
    // Open SCM
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        fprintf(stderr, "[winiptables] OpenSCManager failed: %lu\n",
                GetLastError());
        return 1;
    }

    // Open service
    SC_HANDLE svc = OpenServiceA(scm, "winiptables",
                                  SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (!svc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            fprintf(stderr, "[winiptables] Service is not installed.\n");
        } else {
            fprintf(stderr, "[winiptables] OpenService failed: %lu\n", err);
        }
        CloseServiceHandle(scm);
        return 1;
    }

    // If the service is running, stop it first
    SERVICE_STATUS ss{};
    if (QueryServiceStatus(svc, &ss) &&
        ss.dwCurrentState != SERVICE_STOPPED) {
        SERVICE_STATUS stop_status{};
        ControlService(svc, SERVICE_CONTROL_STOP, &stop_status);

        // Wait for the service to stop (up to 10 seconds)
        for (int i = 0; i < 20; ++i) {
            Sleep(500);
            if (QueryServiceStatus(svc, &ss) &&
                ss.dwCurrentState == SERVICE_STOPPED) {
                break;
            }
        }
    }

    // Delete service
    if (!DeleteService(svc)) {
        fprintf(stderr, "[winiptables] DeleteService failed: %lu\n",
                GetLastError());
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return 1;
    }

    fprintf(stdout, "[winiptables] Service uninstalled successfully.\n");

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

}  // namespace winiptables
