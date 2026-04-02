// log.cpp -- Logger implementation

#include "winiptables/log.hpp"

#include "spdlog/pattern_formatter.h"
#include "spdlog/sinks/rotating_file_sink.h"
#include "spdlog/sinks/stdout_color_sinks.h"

namespace winiptables {

// Custom flag formatter: outputs uppercase full level name (DEBUG/INFO/WARN/ERROR/CRITICAL)
class UppercaseLevelFormatter final : public spdlog::custom_flag_formatter {
public:
    void format(const spdlog::details::log_msg& msg,
                const std::tm& /*tm_time*/,
                spdlog::memory_buf_t& dest) override {
        static const char* kNames[] = {
            "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "CRITICAL", "OFF"
        };
        const auto idx = static_cast<int>(msg.level);
        const char* name = (idx >= 0 && idx < 7) ? kNames[idx] : "UNKNOWN";
        dest.append(name, name + strlen(name));
    }

    [[nodiscard]] std::unique_ptr<custom_flag_formatter> clone() const override {
        return spdlog::details::make_unique<UppercaseLevelFormatter>();
    }
};

static std::unique_ptr<spdlog::pattern_formatter> MakeFormatter(const std::string& pattern) {
    auto formatter = std::make_unique<spdlog::pattern_formatter>();
    formatter->add_flag<UppercaseLevelFormatter>('*');
    formatter->set_pattern(pattern);
    return formatter;
}

void Logger::Init(const std::string& log_file) {
    // Format: [timestamp] [PID:TID] [LEVEL] message
    const std::string pattern = "[%Y-%m-%d %H:%M:%S.%e] [%P:%t] [%*] %v";

    // Console sink
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    console_sink->set_formatter(MakeFormatter(pattern));

    // Rotating file sink (10 MB per file, max 3 files, rotate only when full)
    auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
        log_file, 10 * 1024 * 1024, 3, false);
    file_sink->set_formatter(MakeFormatter(pattern));

    logger_ = std::make_shared<spdlog::logger>("winiptables",
        spdlog::sinks_init_list{console_sink, file_sink});

    logger_->set_level(spdlog::level::debug);
    logger_->flush_on(spdlog::level::info);
}

}  // namespace winiptables
