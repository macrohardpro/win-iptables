#pragma once
// ipc_server.hpp — IpcServer declaration (Task 13.1)
// Named-pipe server that creates a dedicated thread for each CLI connection

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace winiptables {

// Command handler callback: takes argv, writes stdout/stderr, returns exit_code
using CommandHandler = std::function<int(
    const std::vector<std::string>& argv,
    std::string& stdout_out,
    std::string& stderr_out)>;

class IpcServer {
public:
    static constexpr const char* kPipeName = R"(\\.\pipe\winiptables)";

    explicit IpcServer(CommandHandler handler);
    ~IpcServer();

    // Non-copyable
    IpcServer(const IpcServer&) = delete;
    IpcServer& operator=(const IpcServer&) = delete;

    // Starts accept loop thread
    void Start();

    // Graceful stop; closes all connections
    void Stop();

private:
    CommandHandler          handler_;
    std::atomic<bool>       running_{false};
    std::thread             accept_thread_;

    // Active connection threads (joined during Stop)
    std::mutex              conn_mutex_;
    std::vector<std::thread> conn_threads_;

    // Event used to wake up the accept loop
    HANDLE                  stop_event_{INVALID_HANDLE_VALUE};

    // Main accept loop
    void AcceptLoop();

    // Handles a single connection
    void HandleConnection(HANDLE pipe);

    // Cleans up finished connection threads
    void CleanupFinishedThreads();
};

}  // namespace winiptables
