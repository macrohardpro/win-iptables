// main.cpp — Service executable entrypoint (Task 14.4)
//
// Command-line options:
//   (none) or "service"    — Run as a Windows service (StartServiceCtrlDispatcher)
//   "--console" or "-c"    — Run in console mode (runs service logic directly, Ctrl+C stops)
//   "install"              — Install the Windows service (Task 14.5)
//   "uninstall"            — Uninstall the Windows service (Task 14.5)
//   "--help" or "-h"       — Show help

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "service.hpp"

#include "winiptables/log.hpp"

#include <cstdio>
#include <string>

static void print_usage(const char* prog) {
    fprintf(stdout,
        "Usage: %s [command]\n"
        "\n"
        "Commands:\n"
        "  (none) | service   Run as Windows service (default)\n"
        "  --console | -c     Run in console mode (Ctrl+C to stop)\n"
        "  install            Install the Windows service\n"
        "  uninstall          Uninstall the Windows service\n"
        "  --help | -h        Show this help message\n"
        "\n"
        "Service name: winiptables\n"
        "Persist path: %%ProgramData%%\\winiptables\\rules.v4\n",
        prog);
}

int main(int argc, char* argv[]) {
    // Parse first argument
    std::string cmd;
    if (argc >= 2) {
        cmd = argv[1];
    }

    // install / uninstall / help: command-line only, no logging needed
    if (cmd == "install") {
        return winiptables::WiniptablesService::Install();
    }
    if (cmd == "uninstall") {
        return winiptables::WiniptablesService::Uninstall();
    }
    if (cmd == "--help" || cmd == "-h") {
        print_usage(argv[0]);
        return 0;
    }

    // Service mode and console mode: initialize logger
    char exe_path[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, exe_path, MAX_PATH);
    std::string exe_dir(exe_path);
    auto sep = exe_dir.rfind('\\');
    if (sep != std::string::npos) exe_dir = exe_dir.substr(0, sep);
    winiptables::Logger::Instance().Init(exe_dir + "\\winiptables-svc.log");

    // Console mode
    if (cmd == "--console" || cmd == "-c") {
        LOG_INFO("Starting in console mode");
        winiptables::WiniptablesService svc;
        return svc.RunAsConsole();
    }

    // Service mode (none or "service")
    LOG_INFO("Starting in service mode");
    winiptables::WiniptablesService svc;
    return svc.RunAsService();
}
