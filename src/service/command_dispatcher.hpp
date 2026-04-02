#pragma once
// command_dispatcher.hpp — CommandDispatcher declaration (Task 13.4)
// Routes parsed commands to the corresponding RuleStore operations

#include "winiptables/rule_store.hpp"
#include "winiptables/persist.hpp"

#include <string>
#include <vector>

namespace winiptables {

class CommandDispatcher {
public:
    // Injects a RuleStore reference via constructor
    explicit CommandDispatcher(RuleStore& store);

    // Dispatches a command: parses argv and routes to RuleStore operations
    // Returns an exit code (0=success, 1=failure)
    int dispatch(const std::vector<std::string>& argv,
                 std::string& stdout_out,
                 std::string& stderr_out);

    // Builds a Rule from rule_args (matches + target).
    // Public so RulePersist can reuse it when loading rules from file.
    static Rule build_rule(const std::vector<std::string>& rule_args,
                           std::string& err);

private:
    RuleStore& store_;

    // Parses a table name string into TableKind
    static TableKind parse_table(const std::string& name);

    // Parses a target string into Target
    static Target parse_target(const std::string& target_str);

    // Formats a chain rule list into out
    void format_chain_list(TableKind table, const std::string& chain_name,
                           bool numeric, bool verbose, bool line_numbers,
                           std::string& out) const;

    // Formats a single rule as iptables-style text
    static std::string format_rule(const Rule& rule, int num,
                                   bool numeric, bool verbose,
                                   bool line_numbers);
};

}  // namespace winiptables
