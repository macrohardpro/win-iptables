// main.cpp — CLI entrypoint (Task 12.3 / 12.4 / 12.5)
// Parse args → service subcommands call SCM APIs directly
//            → other commands are sent to the service via IpcClient

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winsvc.h>

#include "ipc_client.hpp"
#include "parser.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

// -----------------------------------------------------------------------
// Get current executable directory
// -----------------------------------------------------------------------
static std::string get_exe_dir() {
    char path[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    std::string s(path);
    auto pos = s.rfind('\\');
    if (pos != std::string::npos) s = s.substr(0, pos);
    return s;
}

// -----------------------------------------------------------------------
// Task 12.4: service subcommands
// -----------------------------------------------------------------------

static int service_install() {
    std::string svc_path = get_exe_dir() + "\\winiptables-svc.exe";

    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        fprintf(stderr, "winiptables: failed to open Service Control Manager (error %lu)\n",
                GetLastError());
        return 1;
    }

    SC_HANDLE svc = CreateServiceA(
        scm,
        "winiptables",                    // service name
        "winiptables Firewall Service",   // display name
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,               // automatic start
        SERVICE_ERROR_NORMAL,
        svc_path.c_str(),
        nullptr, nullptr, nullptr,
        nullptr, nullptr                  // LocalSystem account
    );

    if (!svc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            fprintf(stderr, "winiptables: service already exists\n");
        } else {
            fprintf(stderr, "winiptables: failed to install service (error %lu)\n", err);
        }
        CloseServiceHandle(scm);
        return 1;
    }

    printf("winiptables: service installed successfully\n");
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

static int service_start() {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        fprintf(stderr, "winiptables: failed to open Service Control Manager (error %lu)\n",
                GetLastError());
        return 1;
    }

    SC_HANDLE svc = OpenServiceA(scm, "winiptables", SERVICE_START | SERVICE_QUERY_STATUS);
    if (!svc) {
        fprintf(stderr, "winiptables: service not found; run 'service install' first (error %lu)\n",
                GetLastError());
        CloseServiceHandle(scm);
        return 1;
    }

    if (!StartServiceA(svc, 0, nullptr)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            fprintf(stderr, "winiptables: service is already running\n");
        } else {
            fprintf(stderr, "winiptables: failed to start service (error %lu)\n", err);
        }
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return 1;
    }

    printf("winiptables: service started successfully\n");
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

static int service_stop() {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        fprintf(stderr, "winiptables: failed to open Service Control Manager (error %lu)\n",
                GetLastError());
        return 1;
    }

    SC_HANDLE svc = OpenServiceA(scm, "winiptables",
                                  SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!svc) {
        fprintf(stderr, "winiptables: service not found (error %lu)\n", GetLastError());
        CloseServiceHandle(scm);
        return 1;
    }

    SERVICE_STATUS status{};
    if (!ControlService(svc, SERVICE_CONTROL_STOP, &status)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_NOT_ACTIVE) {
            fprintf(stderr, "winiptables: service is not running\n");
        } else {
            fprintf(stderr, "winiptables: failed to stop service (error %lu)\n", err);
        }
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return 1;
    }

    printf("winiptables: service stopped successfully\n");
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

static int service_uninstall() {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        fprintf(stderr, "winiptables: failed to open Service Control Manager (error %lu)\n",
                GetLastError());
        return 1;
    }

    SC_HANDLE svc = OpenServiceA(scm, "winiptables", DELETE | SERVICE_STOP);
    if (!svc) {
        fprintf(stderr, "winiptables: service not found (error %lu)\n", GetLastError());
        CloseServiceHandle(scm);
        return 1;
    }

    // Try to stop the service first
    SERVICE_STATUS status{};
    ControlService(svc, SERVICE_CONTROL_STOP, &status);

    if (!DeleteService(svc)) {
        fprintf(stderr, "winiptables: failed to uninstall service (error %lu)\n", GetLastError());
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return 1;
    }

    printf("winiptables: service uninstalled successfully\n");
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

static int handle_service(const std::string& action) {
    if (action == "install")   return service_install();
    if (action == "start")     return service_start();
    if (action == "stop")      return service_stop();
    if (action == "uninstall") return service_uninstall();
    fprintf(stderr, "winiptables: unknown service action: %s\n", action.c_str());
    return 1;
}

// -----------------------------------------------------------------------
// Task 12.5: iptables-save / iptables-restore via IPC to the service
// -----------------------------------------------------------------------

static int handle_save(const winiptables::cli::ParsedCommand& cmd,
                       int /*argc*/, char* /*argv*/[]) {
    // Build argv to send to the service (starts with "iptables-save")
    std::vector<std::string> ipc_argv;
    ipc_argv.push_back("iptables-save");
    if (!cmd.table.empty() && cmd.table != "filter") {
        ipc_argv.push_back("-t");
        ipc_argv.push_back(cmd.table);
    }
    if (!cmd.file_path.empty()) {
        ipc_argv.push_back("-f");
        ipc_argv.push_back(cmd.file_path);
    }

    auto resp = winiptables::cli::IpcClient::send(ipc_argv);
    if (!resp.error.empty()) {
        fprintf(stderr, "%s\n", resp.error.c_str());
        return 1;
    }
    if (!resp.stdout_text.empty()) fputs(resp.stdout_text.c_str(), stdout);
    if (!resp.stderr_text.empty()) fputs(resp.stderr_text.c_str(), stderr);
    return resp.exit_code;
}

static int handle_restore(const winiptables::cli::ParsedCommand& cmd,
                          int /*argc*/, char* /*argv*/[]) {
    std::vector<std::string> ipc_argv;
    ipc_argv.push_back("iptables-restore");
    if (cmd.noflush) ipc_argv.push_back("--noflush");
    if (!cmd.file_path.empty()) {
        ipc_argv.push_back("-f");
        ipc_argv.push_back(cmd.file_path);
    }

    auto resp = winiptables::cli::IpcClient::send(ipc_argv);
    if (!resp.error.empty()) {
        fprintf(stderr, "%s\n", resp.error.c_str());
        return 1;
    }
    if (!resp.stdout_text.empty()) fputs(resp.stdout_text.c_str(), stdout);
    if (!resp.stderr_text.empty()) fputs(resp.stderr_text.c_str(), stderr);
    return resp.exit_code;
}

// -----------------------------------------------------------------------
// Convert ParsedCommand into argv to send to the service
// -----------------------------------------------------------------------
static std::vector<std::string> build_ipc_argv(
    const winiptables::cli::ParsedCommand& /*cmd*/,
    int argc, char* argv[])
{
    // Pass raw argv[1..] to the service (service parses it)
    std::vector<std::string> ipc_argv;
    for (int i = 1; i < argc; ++i) {
        ipc_argv.push_back(argv[i]);
    }
    return ipc_argv;
}

}  // anonymous namespace

// -----------------------------------------------------------------------
// main
// -----------------------------------------------------------------------
int main(int argc, char* argv[]) {
    using namespace winiptables::cli;

    // Parse command line
    ParsedCommand cmd = CommandParser::parse(argc, argv);

    // Parse error
    if (!cmd.error.empty()) {
        fprintf(stderr, "winiptables: %s\n", cmd.error.c_str());
        CommandParser::print_usage(argv[0]);
        return 1;
    }

    // Help
    if (cmd.verb == "-h") {
        CommandParser::print_usage(argv[0]);
        return 0;
    }

    // service subcommand: call SCM APIs directly (no IPC)
    if (!cmd.service_action.empty()) {
        return handle_service(cmd.service_action);
    }

    // iptables-save
    if (cmd.is_save) {
        return handle_save(cmd, argc, argv);
    }

    // iptables-restore
    if (cmd.is_restore) {
        return handle_restore(cmd, argc, argv);
    }

    // Regular iptables command: send to service via IPC
    std::vector<std::string> ipc_argv = build_ipc_argv(cmd, argc, argv);

    IpcResponse resp = IpcClient::send(ipc_argv);

    // Connection/communication error
    if (!resp.error.empty()) {
        fprintf(stderr, "%s\n", resp.error.c_str());
        return 1;
    }

    // Print service response
    if (!resp.stdout_text.empty()) {
        fputs(resp.stdout_text.c_str(), stdout);
        // Ensure output ends with a newline
        if (resp.stdout_text.back() != '\n') fputc('\n', stdout);
    }
    if (!resp.stderr_text.empty()) {
        fputs(resp.stderr_text.c_str(), stderr);
        if (resp.stderr_text.back() != '\n') fputc('\n', stderr);
    }

    return resp.exit_code;
}
