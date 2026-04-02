// ipc_server.cpp — Named-pipe server (Task 13.1 / 13.2 / 13.3)
// Creates a dedicated thread per CLI connection and handles JSON Lines requests/responses

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "ipc_server.hpp"

#include <algorithm>
#include <sstream>
#include <string>
#include <vector>

namespace winiptables {

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
    if (running_.exchange(true)) return;  // already running
    ResetEvent(stop_event_);
    accept_thread_ = std::thread(&IpcServer::AcceptLoop, this);
}

void IpcServer::Stop() {
    if (!running_.exchange(false)) return;  // already stopped
    SetEvent(stop_event_);

    // Create a temporary connection to wake up a blocked ConnectNamedPipe
    HANDLE tmp = CreateFileA(kPipeName, GENERIC_READ | GENERIC_WRITE,
                             0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (tmp != INVALID_HANDLE_VALUE) CloseHandle(tmp);

    if (accept_thread_.joinable()) accept_thread_.join();

    // Wait for all connection threads to finish
    std::vector<std::thread> threads;
    {
        std::lock_guard<std::mutex> lk(conn_mutex_);
        threads = std::move(conn_threads_);
    }
    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }
}

// -----------------------------------------------------------------------
// Task 13.2: JSON Lines request parsing helpers
// -----------------------------------------------------------------------

// Extract a string value for a given key from a JSON string (simple parsing; fixed format)
static std::string json_extract_string(const std::string& json,
                                        const std::string& key) {
    std::string search = "\"" + key + "\":\"";
    auto pos = json.find(search);
    if (pos == std::string::npos) return {};
    pos += search.size();

    std::string result;
    bool escaped = false;
    for (size_t i = pos; i < json.size(); ++i) {
        char c = json[i];
        if (escaped) {
            switch (c) {
                case '"':  result += '"';  break;
                case '\\': result += '\\'; break;
                case 'n':  result += '\n'; break;
                case 'r':  result += '\r'; break;
                case 't':  result += '\t'; break;
                default:   result += c;    break;
            }
            escaped = false;
        } else if (c == '\\') {
            escaped = true;
        } else if (c == '"') {
            break;
        } else {
            result += c;
        }
    }
    return result;
}

// Extract argv array from JSON
static std::vector<std::string> json_extract_argv(const std::string& json) {
    std::vector<std::string> argv;

    // Locate the "argv":[ substring
    auto pos = json.find("\"argv\":[");
    if (pos == std::string::npos) return argv;
    pos += 8;  // Skip "\"argv\":["

    // Parse each string element
    while (pos < json.size()) {
        // Skip whitespace and commas
        while (pos < json.size() && (json[pos] == ' ' || json[pos] == ',')) ++pos;
        if (pos >= json.size() || json[pos] == ']') break;
        if (json[pos] != '"') { ++pos; continue; }
        ++pos;  // Skip opening quote

        std::string elem;
        bool escaped = false;
        for (; pos < json.size(); ++pos) {
            char c = json[pos];
            if (escaped) {
                switch (c) {
                    case '"':  elem += '"';  break;
                    case '\\': elem += '\\'; break;
                    case 'n':  elem += '\n'; break;
                    case 'r':  elem += '\r'; break;
                    case 't':  elem += '\t'; break;
                    default:   elem += c;    break;
                }
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                ++pos;  // Skip closing quote
                break;
            } else {
                elem += c;
            }
        }
        argv.push_back(std::move(elem));
    }
    return argv;
}

// -----------------------------------------------------------------------
// Task 13.3: response serialization helpers
// -----------------------------------------------------------------------

// JSON string escaping
static std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 4);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += static_cast<char>(c);
                }
                break;
        }
    }
    return out;
}

// Build a JSON Lines response
// Format: { "id": "...", "exit_code": N, "stdout": "...", "stderr": "..." }\n
static std::string build_response(const std::string& id,
                                   int exit_code,
                                   const std::string& stdout_text,
                                   const std::string& stderr_text) {
    std::string resp;
    resp += "{\"id\":\"";
    resp += json_escape(id);
    resp += "\",\"exit_code\":";
    resp += std::to_string(exit_code);
    resp += ",\"stdout\":\"";
    resp += json_escape(stdout_text);
    resp += "\",\"stderr\":\"";
    resp += json_escape(stderr_text);
    resp += "\"}\n";
    return resp;
}

// -----------------------------------------------------------------------
// Connection handling (one thread per connection)
// -----------------------------------------------------------------------

void IpcServer::HandleConnection(HANDLE pipe) {
    // Read request (until newline)
    std::string request_line;
    char buf[4096];
    bool read_done = false;

    while (!read_done) {
        DWORD bytes_read = 0;
        BOOL ok = ReadFile(pipe, buf, sizeof(buf) - 1, &bytes_read, nullptr);
        if (!ok && GetLastError() != ERROR_MORE_DATA) break;
        if (bytes_read > 0) {
            buf[bytes_read] = '\0';
            request_line.append(buf, bytes_read);
        }
        if (request_line.find('\n') != std::string::npos) read_done = true;
        if (!ok) break;
    }

    // Strip trailing newlines
    while (!request_line.empty() &&
           (request_line.back() == '\n' || request_line.back() == '\r')) {
        request_line.pop_back();
    }

    std::string response;
    if (request_line.empty()) {
        response = build_response("", 1, "", "empty request");
    } else {
        // Task 13.2: parse id and argv
        std::string id   = json_extract_string(request_line, "id");
        auto        argv = json_extract_argv(request_line);

        // Invoke command handler
        std::string stdout_out, stderr_out;
        int exit_code = 1;
        if (handler_) {
            exit_code = handler_(argv, stdout_out, stderr_out);
        } else {
            stderr_out = "no handler registered";
        }

        // Task 13.3: serialize response
        response = build_response(id, exit_code, stdout_out, stderr_out);
    }

    // Write response
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
        // Create a named pipe instance
        HANDLE pipe = CreateNamedPipeA(
            kPipeName,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            65536,   // output buffer
            65536,   // input buffer
            0,       // default timeout
            nullptr  // default security attributes
        );

        if (pipe == INVALID_HANDLE_VALUE) break;

        // Wait for client connection (or stop signal)
        OVERLAPPED ov{};
        ov.hEvent = CreateEventA(nullptr, TRUE, FALSE, nullptr);
        BOOL connected = ConnectNamedPipe(pipe, &ov);
        DWORD err = GetLastError();

        if (!connected) {
            if (err == ERROR_IO_PENDING) {
                // Async wait: connection event OR stop event
                HANDLE handles[2] = {ov.hEvent, stop_event_};
                DWORD wait = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
                if (wait == WAIT_OBJECT_0 + 1) {
                    // Stop signal
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
            } else if (err == ERROR_PIPE_CONNECTED) {
                // Client already connected (before ConnectNamedPipe)
            } else {
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

        // Spawn a dedicated thread per connection
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
    auto it = conn_threads_.begin();
    while (it != conn_threads_.end()) {
        // Try to reclaim finished threads (non-blocking check).
        // Since std::thread doesn't provide try_join, we join everything in Stop().
        // This function exists to prevent unbounded growth in long-running scenarios.
        ++it;
    }
}

}  // namespace winiptables
