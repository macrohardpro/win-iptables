#pragma once
// log.hpp -- Logger singleton wrapper for spdlog

#include "spdlog/spdlog.h"
#include "spdlog/sinks/rotating_file_sink.h"
#include "spdlog/sinks/stdout_color_sinks.h"

#include <memory>
#include <string>

namespace winiptables {

class Logger {
public:
    // Get singleton instance
    static Logger& Instance() {
        static Logger instance;
        return instance;
    }

    // Initialize logging system
    void Init(const std::string& log_file = "winiptables.log");

    // Get spdlog instance
    std::shared_ptr<spdlog::logger>& GetLogger() {
        return logger_;
    }

private:
    Logger() = default;
    ~Logger() = default;

    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    std::shared_ptr<spdlog::logger> logger_;
};

// Logging macros
#ifdef _DEBUG
#define LOG_DEBUG(...) ::winiptables::Logger::Instance().GetLogger()->debug(__VA_ARGS__)
#else
#define LOG_DEBUG(...) do {} while(0)
#endif

#define LOG_INFO(...) ::winiptables::Logger::Instance().GetLogger()->info(__VA_ARGS__)
#define LOG_WARN(...) ::winiptables::Logger::Instance().GetLogger()->warn(__VA_ARGS__)
#define LOG_ERROR(...) ::winiptables::Logger::Instance().GetLogger()->error(__VA_ARGS__)
#define LOG_CRITICAL(...) ::winiptables::Logger::Instance().GetLogger()->critical(__VA_ARGS__)

}  // namespace winiptables