#pragma once
// ipc_client.hpp — IpcClient declaration (Task 12.2)

#include <string>
#include <vector>

namespace winiptables {
namespace cli {

// IPC response structure
struct IpcResponse {
    int         exit_code = 0;
    std::string stdout_text;
    std::string stderr_text;
    std::string error;  // connection/communication error (non-empty means failure)
};

class IpcClient {
public:
    // Sends argv over a named pipe and returns the service response
    // If connection fails, response.error is non-empty
    static IpcResponse send(const std::vector<std::string>& argv);

private:
    static constexpr const char* kPipeName = R"(\\.\pipe\winiptables)";

    // Generates a unique request ID (simple counter)
    static std::string generate_id();

    // JSON string escaping
    static std::string json_escape(const std::string& s);

    // Build JSON Lines request
    static std::string build_request(const std::string& id,
                                     const std::vector<std::string>& argv);

    // Parse JSON Lines response
    static IpcResponse parse_response(const std::string& line);
};

}  // namespace cli
}  // namespace winiptables
