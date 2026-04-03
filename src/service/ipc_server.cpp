// ipc_server.cpp — Named-pipe server
// Creates a dedicated thread per CLI connection and handles JSON Lines requests/responses

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "ipc_server.hpp"

#include "nlohmann/json.hpp"

#include <string>
#include <vector>

namespace winiptables {

using json = nlohmann::json;

// -----------------------------------------------------------------------
// Ctor / dtor
// -----------------------------------------------------------------------

IpcServer::IpcServer(CommandHandler handler)
    : handler_(std::move(handler)) {
    stop_event_ = CreateEventA(nullptr, TRUE, FALSE, nullptr);
}

IpcServer::~IpcServer() {
    Stop();
    if (stop_event_ != INVALID_HANDLE_VALUE) {
        CloseHandle(stop_event_);
        stop_event_ = INVALID_HANDLE_VALUE;
    }
}

// -----------------------------------------------------------------------
// Start / Stop
// -----------------------------------------------------------------------

void IpcServer::Start() {
    if (running_.exchange(true)) { return; }
    ResetEvent(stop_event_);
    accept_thread_ = std::thread(&IpcServer::AcceptLoop, this);
}

void IpcServer::Stop() {
    if (!running_.exchange(false)) { return; }
    SetEvent(stop_event_);

    // Wake up a blocked ConnectNamedPipe
    HANDLE tmp = CreateFileA(kPipeName, GENERIC_READ | GENERIC_WRITE,
                             0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (tmp != INVALID_HANDLE_VALUE) { CloseHandle(tmp); }

    if (accept_thread_.joinable()) { accept_thread_.join(); }

    std::vector<std::thread> threads;
    {
        std::lock_guard<std::mutex> lk(conn_mutex_);
        threads = std::move(conn_threads_);
    }
    for (auto& t : threads) {
        if (t.joinable()) { t.join(); }
    }
}

// -----------------------------------------------------------------------
// Request parsing
// -----------------------------------------------------------------------

// Parse a JSON Lines request line; returns false on malformed input.
static bool parse_request(const std::string& line,
                           std::string& out_id,
                           std::vector<std::string>& out_argv) {
    try {
        auto j   = json::parse(line);
        out_id   = j.value("id", "");
        out_argv = j.value("argv", std::vector<std::string>{});
        return true;
    } catch (const json::exception&) {
        return false;
    }
}

// -----------------------------------------------------------------------
// Response serialization
// -----------------------------------------------------------------------

// Build a JSON Lines response: {"id":"...","exit_code":N,"stdout":"...","stderr":"..."}\n
static std::string build_response(const std::string& id,
                                   int exit_code,
                                   const std::string& stdout_text,
                                   const std::string& stderr_text) {
    json resp;
    resp["id"]        = id;
    resp["exit_code"] = exit_code;
    resp["stdout"]    = stdout_text;
    resp["stderr"]    = stderr_text;
    return resp.dump() + "\n";
}

// -----------------------------------------------------------------------
// Connection handling (one thread per connection)
// -----------------------------------------------------------------------

void IpcServer::HandleConnection(HANDLE pipe) {
    // Read request until newline
    std::string request_line;
    char buf[4096];
    bool read_done = false;

    while (!read_done) {
        DWORD bytes_read = 0;
        BOOL ok = ReadFile(pipe, buf, sizeof(buf) - 1, &bytes_read, nullptr);
        if (!ok && GetLastError() != ERROR_MORE_DATA) { break; }
        if (bytes_read > 0) {
            buf[bytes_read] = '\0';
            request_line.append(buf, bytes_read);
        }
        if (request_line.find('\n') != std::string::npos) { read_done = true; }
        if (!ok) { break; }
    }

    while (!request_line.empty() &&
           (request_line.back() == '\n' || request_line.back() == '\r')) {
        request_line.pop_back();
    }

    std::string response;
    if (request_line.empty()) {
        response = build_response("", 1, "", "empty request");
    } else {
        std::string id;
        std::vector<std::string> argv;

        if (!parse_request(request_line, id, argv)) {
            response = build_response("", 1, "", "malformed JSON request");
        } else {
            std::string stdout_out, stderr_out;
            int exit_code = 1;
            if (handler_) {
                exit_code = handler_(argv, stdout_out, stderr_out);
            } else {
                stderr_out = "no handler registered";
            }
            response = build_response(id, exit_code, stdout_out, stderr_out);
        }
    }

    DWORD written = 0;
    WriteFile(pipe, response.data(), static_cast<DWORD>(response.size()),
              &written, nullptr);

    FlushFileBuffers(pipe);
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
}

// -----------------------------------------------------------------------
// Main accept loop
// -----------------------------------------------------------------------

void IpcServer::AcceptLoop() {
    while (running_.load()) {
        HANDLE pipe = CreateNamedPipeA(
            kPipeName,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            65536,
            65536,
            0,
            nullptr
        );

        if (pipe == INVALID_HANDLE_VALUE) { break; }

        OVERLAPPED ov{};
        ov.hEvent = CreateEventA(nullptr, TRUE, FALSE, nullptr);
        BOOL connected = ConnectNamedPipe(pipe, &ov);
        DWORD err = GetLastError();

        if (!connected) {
            if (err == ERROR_IO_PENDING) {
                HANDLE handles[2] = {ov.hEvent, stop_event_};
                DWORD wait = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
                if (wait == WAIT_OBJECT_0 + 1) {
                    CloseHandle(ov.hEvent);
                    CancelIo(pipe);
                    CloseHandle(pipe);
                    break;
                }
                DWORD transferred = 0;
                if (!GetOverlappedResult(pipe, &ov, &transferred, FALSE)) {
                    CloseHandle(ov.hEvent);
                    CloseHandle(pipe);
                    continue;
                }
            } else if (err != ERROR_PIPE_CONNECTED) {
                CloseHandle(ov.hEvent);
                CloseHandle(pipe);
                continue;
            }
        }
        CloseHandle(ov.hEvent);

        if (!running_.load()) {
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
            break;
        }

        CleanupFinishedThreads();
        {
            std::lock_guard<std::mutex> lk(conn_mutex_);
            conn_threads_.emplace_back([this, pipe]() {
                HandleConnection(pipe);
            });
        }
    }
}

// -----------------------------------------------------------------------
// Cleanup finished connection threads
// -----------------------------------------------------------------------

void IpcServer::CleanupFinishedThreads() {
    std::lock_guard<std::mutex> lk(conn_mutex_);
    // Threads are fully joined in Stop(); this prevents unbounded growth.
    (void)conn_threads_;
}

}  // namespace winiptables
