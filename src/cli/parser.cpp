// parser.cpp — CommandParser implementation (Task 12.1)
// Parses iptables-compatible argc/argv

#include "parser.hpp"

#include <cstring>
#include <string>
#include <vector>

namespace winiptables {
namespace cli {

// Returns true if the string is all digits
static bool is_number(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
    }
    return true;
}

ParsedCommand CommandParser::parse(int argc, char* argv[]) {
    ParsedCommand cmd;

    if (argc < 1) return cmd;

    // argv[0] is the program name; detect iptables-save / iptables-restore
    const char* prog = argv[0];
    {
        // Extract base name (strip path)
        const char* base = prog;
        for (const char* p = prog; *p; ++p) {
            if (*p == '/' || *p == '\\') base = p + 1;
        }
        // Strip .exe suffix before comparing
        std::string name(base);
        auto dot = name.rfind('.');
        if (dot != std::string::npos) name = name.substr(0, dot);

        if (name == "iptables-save") {
            cmd.is_save = true;
        } else if (name == "iptables-restore") {
            cmd.is_restore = true;
        }
    }

    if (argc < 2) {
        // With no arguments, default to -L (iptables-compatible)
        if (!cmd.is_save && !cmd.is_restore) {
            cmd.verb  = "-L";
            cmd.chain = "";
        }
        return cmd;
    }

    // Check for "service" subcommand
    if (std::strcmp(argv[1], "service") == 0) {
        if (argc < 3) {
            cmd.error = "service subcommand requires an action: install/start/stop/uninstall";
            return cmd;
        }
        const char* action = argv[2];
        if (std::strcmp(action, "install")   == 0 ||
            std::strcmp(action, "start")     == 0 ||
            std::strcmp(action, "stop")      == 0 ||
            std::strcmp(action, "uninstall") == 0) {
            cmd.service_action = action;
        } else {
            cmd.error = std::string("Unknown service action: ") + action;
        }
        return cmd;
    }

    // iptables-save / iptables-restore argument parsing
    if (cmd.is_save || cmd.is_restore) {
        for (int i = 1; i < argc; ++i) {
            std::string arg(argv[i]);
            if (arg == "--noflush") {
                cmd.noflush = true;
            } else if ((arg == "-f" || arg == "--file") && i + 1 < argc) {
                cmd.file_path = argv[++i];
            } else if (arg == "-t" && i + 1 < argc) {
                cmd.table = argv[++i];
            } else if (arg[0] != '-') {
                // Positional argument as file path
                cmd.file_path = arg;
            }
        }
        return cmd;
    }

    // Standard iptables argument parsing
    // Flag to start collecting rule arguments (matches and target)
    bool collecting_rule_args = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);

        // Table option
        if (arg == "-t" || arg == "--table") {
            if (i + 1 >= argc) { cmd.error = "-t requires an argument"; return cmd; }
            cmd.table = argv[++i];
            continue;
        }

        // Output options
        if (arg == "-n" || arg == "--numeric") {
            cmd.numeric = true;
            continue;
        }
        if (arg == "-v" || arg == "--verbose") {
            cmd.verbose = true;
            continue;
        }
        if (arg == "--line-numbers") {
            cmd.line_numbers = true;
            continue;
        }

        // Verb (only the first one wins)
        if (cmd.verb.empty()) {
            // Single-letter verbs
            if (arg == "-A" || arg == "--append") {
                cmd.verb = "-A";
                if (i + 1 < argc && argv[i+1][0] != '-') cmd.chain = argv[++i];
                collecting_rule_args = true;
                continue;
            }
            if (arg == "-I" || arg == "--insert") {
                cmd.verb = "-I";
                if (i + 1 < argc && argv[i+1][0] != '-') {
                    cmd.chain = argv[++i];
                    // Optional rule number
                    if (i + 1 < argc && is_number(argv[i+1])) {
                        cmd.rule_num = std::stoi(argv[++i]);
                    } else {
                        cmd.rule_num = 1;
                    }
                }
                collecting_rule_args = true;
                continue;
            }
            if (arg == "-D" || arg == "--delete") {
                cmd.verb = "-D";
                if (i + 1 < argc && argv[i+1][0] != '-') {
                    cmd.chain = argv[++i];
                    // Optional rule number
                    if (i + 1 < argc && is_number(argv[i+1])) {
                        cmd.rule_num = std::stoi(argv[++i]);
                    }
                }
                collecting_rule_args = true;
                continue;
            }
            if (arg == "-R" || arg == "--replace") {
                cmd.verb = "-R";
                if (i + 1 < argc && argv[i+1][0] != '-') {
                    cmd.chain = argv[++i];
                    if (i + 1 < argc && is_number(argv[i+1])) {
                        cmd.rule_num = std::stoi(argv[++i]);
                    }
                }
                collecting_rule_args = true;
                continue;
            }
            if (arg == "-L" || arg == "--list") {
                cmd.verb = "-L";
                if (i + 1 < argc && argv[i+1][0] != '-') cmd.chain = argv[++i];
                continue;
            }
            if (arg == "-S" || arg == "--list-rules") {
                cmd.verb = "-S";
                if (i + 1 < argc && argv[i+1][0] != '-') cmd.chain = argv[++i];
                continue;
            }
            if (arg == "-F" || arg == "--flush") {
                cmd.verb = "-F";
                if (i + 1 < argc && argv[i+1][0] != '-') cmd.chain = argv[++i];
                continue;
            }
            if (arg == "-Z" || arg == "--zero") {
                cmd.verb = "-Z";
                if (i + 1 < argc && argv[i+1][0] != '-') cmd.chain = argv[++i];
                continue;
            }
            if (arg == "-N" || arg == "--new-chain") {
                cmd.verb = "-N";
                if (i + 1 < argc) cmd.chain = argv[++i];
                continue;
            }
            if (arg == "-X" || arg == "--delete-chain") {
                cmd.verb = "-X";
                if (i + 1 < argc && argv[i+1][0] != '-') cmd.chain = argv[++i];
                continue;
            }
            if (arg == "-P" || arg == "--policy") {
                cmd.verb = "-P";
                if (i + 1 < argc) cmd.chain = argv[++i];
                if (i + 1 < argc) cmd.rule_args.push_back(argv[++i]);  // policy target
                continue;
            }
            if (arg == "-E" || arg == "--rename-chain") {
                cmd.verb = "-E";
                if (i + 1 < argc) cmd.chain = argv[++i];
                if (i + 1 < argc) cmd.rule_args.push_back(argv[++i]);  // new name
                continue;
            }
            if (arg == "-C" || arg == "--check") {
                cmd.verb = "-C";
                if (i + 1 < argc && argv[i+1][0] != '-') cmd.chain = argv[++i];
                collecting_rule_args = true;
                continue;
            }
            // Help
            if (arg == "-h" || arg == "--help") {
                cmd.verb = "-h";
                continue;
            }
        }

        // Collect rule arguments (matches and target)
        if (collecting_rule_args || !cmd.verb.empty()) {
            cmd.rule_args.push_back(arg);
        }
    }

    // Default verb
    if (cmd.verb.empty()) {
        cmd.verb = "-L";
    }

    return cmd;
}

void CommandParser::print_usage(const char* prog) {
    fprintf(stderr,
        "Usage: %s [-t table] {-A|-I|-D|-R|-L|-F|-Z|-N|-X|-P|-E} chain [rule args]\n"
        "      %s service {install|start|stop|uninstall}\n"
        "\n"
        "Options:\n"
        "  -t, --table <table>              Select table (filter/nat/mangle), default: filter\n"
        "  -A, --append <chain>             Append rule to end of chain\n"
        "  -I, --insert <chain> [n]         Insert rule into chain (default position: 1)\n"
        "  -D, --delete <chain> [n]         Delete rule\n"
        "  -R, --replace <chain> n          Replace rule\n"
        "  -L, --list [chain]               List rules\n"
        "  -S, --list-rules [chain]         List rules in rule-spec form\n"
        "  -F, --flush [chain]              Flush rules\n"
        "  -Z, --zero [chain]               Zero counters\n"
        "  -N, --new-chain <chain>          Create new chain\n"
        "  -X, --delete-chain [chain]       Delete chain\n"
        "  -P, --policy <chain> <target>    Set default policy\n"
        "  -E, --rename-chain <old> <new>   Rename chain\n"
        "  -n, --numeric                    Numeric output\n"
        "  -v, --verbose                    Verbose output\n"
        "  --line-numbers                   Print line numbers\n"
        "  -h, --help                       Show help\n",
        prog, prog);
}

}  // namespace cli
}  // namespace winiptables
