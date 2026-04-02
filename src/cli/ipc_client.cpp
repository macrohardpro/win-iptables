// ipc_client.cpp — Named-pipe client (Task 12.2)
// Sends JSON Lines requests to \\.\pipe\winiptables and reads responses

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "ipc_client.hpp"

#include <atomic>
#include <sstream>
#include <string>
#include <vector>

namespace winiptables {
namespace cli {

// -----------------------------------------------------------------------
// Generate unique request ID (atomic counter)
// -----------------------------------------------------------------------
std::string IpcClient::generate_id() {
    static std::atomic<uint64_t> counter{1};
    uint64_t id = counter.fetch_add(1, std::memory_order_relaxed);
    return std::to_string(id);
}

// -----------------------------------------------------------------------
// JSON string escaping
// -----------------------------------------------------------------------
std::string IpcClient::json_escape(const std::string& s) {
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

// -----------------------------------------------------------------------
// Build JSON Lines request
// Format: { "id": "...", "argv": ["arg1", "arg2", ...] }\n
// -----------------------------------------------------------------------
std::string IpcClient::build_request(const std::string& id,
                                      const std::vector<std::string>& argv) {
    std::string req;
    req += "{\"id\":\"";
    req += json_escape(id);
    req += "\",\"argv\":[";
    for (size_t i = 0; i < argv.size(); ++i) {
        if (i > 0) req += ',';
        req += '"';
        req += json_escape(argv[i]);
        req += '"';
    }
    req += "]}\n";
    return req;
}

// -----------------------------------------------------------------------
// Parse JSON Lines response
// Format: { "id": "...", "exit_code": 0, "stdout": "...", "stderr": "..." }
// Uses simple string parsing (fixed format)
// -----------------------------------------------------------------------

// Extract a string value for a given key from a JSON string
static std::string extract_string(const std::string& json, const std::string& key) {
    // Find "key":"
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

// Extract an integer value from JSON
static int extract_int(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\":";
    auto pos = json.find(search);
    if (pos == std::string::npos) return 0;
    pos += search.size();
    // Skip whitespace
    while (pos < json.size() && json[pos] == ' ') ++pos;
    int val = 0;
    bool neg = false;
    if (pos < json.size() && json[pos] == '-') { neg = true; ++pos; }
    while (pos < json.size() && json[pos] >= '0' && json[pos] <= '9') {
        val = val * 10 + (json[pos] - '0');
        ++pos;
    }
    return neg ? -val : val;
}

IpcResponse IpcClient::parse_response(const std::string& line) {
    IpcResponse resp;
    resp.exit_code   = extract_int(line, "exit_code");
    resp.stdout_text = extract_string(line, "stdout");
    resp.stderr_text = extract_string(line, "stderr");
    return resp;
}

// -----------------------------------------------------------------------
// Main send function
// -----------------------------------------------------------------------
IpcResponse IpcClient::send(const std::vector<std::string>& argv) {
    IpcResponse resp;

    // Try to connect to named pipe
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

    // Set pipe read mode (if supported by server)
    DWORD mode = PIPE_READMODE_BYTE;
    SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr);

    // Build and send request
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

    // Read response (until newline)
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

        // Stop when a newline is found
        if (response_line.find('\n') != std::string::npos) break;
        if (!read_ok) break;
    }

    CloseHandle(pipe);

    // Strip trailing newlines
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
