// test_log.cpp -- Test logger functionality

#include "winiptables/log.hpp"

int main() {
    // Initialize logging system
    winiptables::Logger::Instance().Init();

    // Test various log levels
    LOG_DEBUG("This is a debug message (only in Debug build)");
    LOG_INFO("This is an info message");
    LOG_WARN("This is a warning message");
    LOG_ERROR("This is an error message");
    LOG_CRITICAL("This is a critical message");

    // Test log with parameters
    int port = 8080;
    std::string ip = "192.168.1.1";
    LOG_INFO("Server started on {}:{}", ip, port);

    return 0;
}