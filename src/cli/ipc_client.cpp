// ipc_client.cpp — Named-pipe client
// Sends JSON Lines requests to \\.\pipe\winiptables and reads responses

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "ipc_client.hpp"

#include "nlohmann/json.hpp"

#include <atomic>
#include <string>
#include <vector>

namespace winiptables {
namespace cli {

using json = nlohmann::json;

// -----------------------------------------------------------------------
// Generate unique request ID (atomic counter)
// -----------------------------------------------------------------------
std::string IpcClient::generate_id() {
    static std::atomic<uint64_t> counter{1};
    return std::to_string(counter.fetch_add(1, std::memory_order_relaxed));
}

// -----------------------------------------------------------------------
// Build JSON Lines request: {"id":"...","argv":["arg1","arg2",...]}\n
// -----------------------------------------------------------------------
std::string IpcClient::build_request(const std::string& id,
                                      const std::vector<std::string>& argv) {
    json req;
    req["id"]   = id;
    req["argv"] = argv;
    return req.dump() + "\n";
}

// -----------------------------------------------------------------------
// Parse JSON Lines response
// Format: {"id":"...","exit_code":N,"stdout":"...","stderr":"..."}
// -----------------------------------------------------------------------
IpcResponse IpcClient::parse_response(const std::string& line) {
    IpcResponse resp;
    try {
        auto j           = json::parse(line);
        resp.exit_code   = j.value("exit_code", 1);
        resp.stdout_text = j.value("stdout", "");
        resp.stderr_text = j.value("stderr", "");
    } catch (const json::exception& e) {
        resp.exit_code = 1;
        resp.stderr_text = std::string("winiptables: failed to parse response: ") + e.what();
    }
    return resp;
}

// -----------------------------------------------------------------------
// Main send function
// -----------------------------------------------------------------------
IpcResponse IpcClient::send(const std::vector<std::string>& argv) {
    IpcResponse resp;

    HANDLE pipe = CreateFileA(
        kPipeName,
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr
    );

    if (pipe == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PIPE_BUSY) {
            resp.error = "winiptables: service is not running; start it first\n"
                         "  Hint: winiptables service start";
        } else {
            char buf[256];
            snprintf(buf, sizeof(buf),
                     "winiptables: failed to connect to service (error %lu)", err);
            resp.error = buf;
        }
        return resp;
    }

    DWORD mode = PIPE_READMODE_BYTE;
    SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr);

    std::string id  = generate_id();
    std::string req = build_request(id, argv);

    DWORD written = 0;
    BOOL ok = WriteFile(pipe, req.data(), static_cast<DWORD>(req.size()),
                        &written, nullptr);
    if (!ok || written != static_cast<DWORD>(req.size())) {
        resp.error = "winiptables: failed to send request";
        CloseHandle(pipe);
        return resp;
    }

    // Read response until newline
    std::string response_line;
    char buf[4096];
    while (true) {
        DWORD read_bytes = 0;
        BOOL read_ok = ReadFile(pipe, buf, sizeof(buf) - 1, &read_bytes, nullptr);
        if (!read_ok && GetLastError() != ERROR_MORE_DATA) {
            if (response_line.empty()) {
                resp.error = "winiptables: failed to read response";
                CloseHandle(pipe);
                return resp;
            }
            break;
        }
        buf[read_bytes] = '\0';
        response_line.append(buf, read_bytes);
        if (response_line.find('\n') != std::string::npos) { break; }
        if (!read_ok) { break; }
    }

    CloseHandle(pipe);

    while (!response_line.empty() &&
           (response_line.back() == '\n' || response_line.back() == '\r')) {
        response_line.pop_back();
    }

    if (response_line.empty()) {
        resp.error = "winiptables: received empty response";
        return resp;
    }

    return parse_response(response_line);
}

}  // namespace cli
}  // namespace winiptables
