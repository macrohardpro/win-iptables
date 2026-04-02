#pragma once
// parser.hpp — CommandParser declaration (Task 12.1)

#include <string>
#include <vector>

namespace winiptables {
namespace cli {

// Parsed command structure
struct ParsedCommand {
    // Table name (-t), default: filter
    std::string table = "filter";

    // Verb (-A/-I/-D/-R/-L/-F/-Z/-N/-X/-P/-E)
    std::string verb;

    // Chain name
    std::string chain;

    // Rule number (used by -I/-D/-R, 1-based)
    int rule_num = 0;

    // Rule arguments (matches + target; parsed by the service)
    std::vector<std::string> rule_args;

    // Output options
    bool numeric      = false;  // -n
    bool verbose      = false;  // -v
    bool line_numbers = false;  // --line-numbers

    // service subcommand
    std::string service_action;  // install/start/stop/uninstall

    // save/restore subcommands
    bool        is_save    = false;
    bool        is_restore = false;
    bool        noflush    = false;   // --noflush (for restore)
    std::string file_path;            // -f <file> or last non-option argument

    // Parse error message (non-empty means parsing failed)
    std::string error;
};

class CommandParser {
public:
    // Parses argc/argv and returns ParsedCommand
    // argv[0] is the program name; parsing starts from argv[1]
    static ParsedCommand parse(int argc, char* argv[]);

    // Prints usage to stderr
    static void print_usage(const char* prog);
};

}  // namespace cli
}  // namespace winiptables
