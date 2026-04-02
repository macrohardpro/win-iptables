#pragma once
// service.hpp — WiniptablesService declaration
// Windows service state machine wrapping ServiceMain / HandlerEx callbacks

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "winiptables/capture.hpp"
#include "winiptables/persist.hpp"
#include "winiptables/rule_store.hpp"
#include "winiptables/stateful.hpp"
#include "winiptables/table_pipeline.hpp"

#include "command_dispatcher.hpp"
#include "ipc_server.hpp"

#include <memory>
#include <string>

namespace winiptables {

// Persist file path (%ProgramData%\winiptables\rules.v4)
std::string GetPersistPath();

// Ensure the persist directory exists
void EnsurePersistDir();

// -----------------------------------------------------------------------
// WiniptablesService — service state machine
// -----------------------------------------------------------------------
class WiniptablesService {
public:
    WiniptablesService();
    ~WiniptablesService();

    // Non-copyable, non-movable
    WiniptablesService(const WiniptablesService&) = delete;
    WiniptablesService& operator=(const WiniptablesService&) = delete;

    // ── Service mode entry ────────────────────────────────────────────────────

    // Register ServiceMain and call StartServiceCtrlDispatcher (blocks until stopped)
    int RunAsService();

    // ── Console mode entry ────────────────────────────────────────────────────

    // Start service logic directly, blocks until Ctrl+C or Stop() is called
    int RunAsConsole();

    // ── Install / Uninstall ───────────────────────────────────────────────────

    static int Install();
    static int Uninstall();

    // ── Static SCM callbacks ──────────────────────────────────────────────────

    static VOID WINAPI ServiceMain(DWORD argc, LPSTR* argv);
    static DWORD WINAPI HandlerEx(DWORD control, DWORD event_type,
                                   LPVOID event_data, LPVOID context);

    // ── Lifecycle (public, called by HandlerEx and console Ctrl+C handler) ────

    bool Start();
    void Stop();

    // Stop event handle (public, waited on by ServiceMain and signalled by HandlerEx)
    HANDLE stop_event_{INVALID_HANDLE_VALUE};

private:
    // ── SCM status reporting ──────────────────────────────────────────────────

    void ReportStatus(DWORD state, DWORD exit_code = NO_ERROR,
                      DWORD wait_hint = 0);

    // ── Member variables ──────────────────────────────────────────────────────

    SERVICE_STATUS_HANDLE   status_handle_{nullptr};
    SERVICE_STATUS          status_{};

    // Core components (declared in startup order, destroyed in reverse)
    std::unique_ptr<RuleStore>          store_;
    std::unique_ptr<StatefulTracker>    tracker_;
    std::unique_ptr<TablePipeline>      pipeline_;
    std::unique_ptr<PacketCapture>      capture_;
    std::unique_ptr<CommandDispatcher>  dispatcher_;
    std::unique_ptr<IpcServer>          ipc_server_;

    // ── Global singleton ──────────────────────────────────────────────────────
    static WiniptablesService* instance_;
};

}  // namespace winiptables
