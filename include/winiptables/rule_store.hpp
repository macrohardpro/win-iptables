#pragma once
// rule_store.hpp -- RuleStore declarations (Task 6.1)
// Thread-safe rule storage managing all table/chain/rule CRUD operations

#include "winiptables/model.hpp"

#include <functional>
#include <shared_mutex>
#include <string>
#include <vector>

namespace winiptables {

// Operation result: success or failure with error message
struct StoreResult {
    bool        ok      = true;
    std::string message;  // Error description on failure

    static StoreResult Ok() { return {true, {}}; }
    static StoreResult Err(std::string msg) { return {false, std::move(msg)}; }
    explicit operator bool() const { return ok; }
};

class RuleStore {
public:
    // Initializes builtin tables and chains on construction
    RuleStore();

    // -----------------------------------------------------------------------
    // Chain management
    // -----------------------------------------------------------------------

    // -N: create a user-defined chain in the specified table
    StoreResult create_chain(TableKind table, const std::string& chain_name);

    // -X: delete a user-defined chain (chain must be empty and not referenced)
    StoreResult delete_chain(TableKind table, const std::string& chain_name);

    // -P: set default policy for builtin chains (user-defined chains cannot have policies)
    StoreResult set_policy(TableKind table, const std::string& chain_name, Target policy);

    // -E: rename a user-defined chain
    StoreResult rename_chain(TableKind table,
                             const std::string& old_name,
                             const std::string& new_name);

    // -----------------------------------------------------------------------
    // Rule management
    // -----------------------------------------------------------------------

    // -A: append rule to the end of a chain
    StoreResult append_rule(TableKind table, const std::string& chain_name, Rule rule);

    // -I: insert rule at specified position (rulenum starts at 1, default 1)
    StoreResult insert_rule(TableKind table, const std::string& chain_name,
                            Rule rule, int rulenum = 1);

    // -D <rulenum>: delete rule by 1-based number
    StoreResult delete_rule_by_num(TableKind table, const std::string& chain_name,
                                   int rulenum);

    // -D <rule-spec>: delete first rule matching the spec
    // match_fn accepts const Rule& and returns bool, used to compare rule equivalence
    StoreResult delete_rule_by_spec(TableKind table, const std::string& chain_name,
                                    std::function<bool(const Rule&)> match_fn);

    // -R: replace rule at specified position (rulenum starts at 1)
    StoreResult replace_rule(TableKind table, const std::string& chain_name,
                             int rulenum, Rule rule);

    // -L: list all rules in specified chain (returns read-only pointers, valid while caller holds shared lock)
    // Note: return value may be invalidated after next write operation, use only for immediate reading
    std::vector<const Chain*> list_chains(TableKind table) const;

    // Get a single chain (used by rule engine evaluation, returns nullptr if not exists)
    const Chain* get_chain(TableKind table, const std::string& chain_name) const;

    // Cross-table chain lookup (used by rule engine for JUMP)
    const Chain* get_chain_any_table(const std::string& chain_name) const;

    // -----------------------------------------------------------------------
    // Counter operations
    // -----------------------------------------------------------------------

    // -Z: zero rule counters for specified chain (or all chains)
    // If chain_name is empty, zeros all chains in the table
    StoreResult zero_counters(TableKind table, const std::string& chain_name = "");

    // -----------------------------------------------------------------------
    // Helper utilities
    // -----------------------------------------------------------------------

    // Validate chain name (max 29 chars, only letters/digits/hyphen/underscore)
    static bool is_valid_chain_name(const std::string& name);

private:
    mutable std::shared_mutex                    mutex_;
    std::unordered_map<TableKind, Table>         tables_;

    // Internal implementation (caller must hold appropriate lock)
    Table*       get_table(TableKind kind);
    const Table* get_table(TableKind kind) const;

    Chain*       get_chain_locked(TableKind table, const std::string& name);
    const Chain* get_chain_locked(TableKind table, const std::string& name) const;

    // Check if chain is referenced by any rule in any table (used for -X pre-check)
    bool is_chain_referenced(const std::string& chain_name) const;

    void init_builtin_tables();
};

}  // namespace winiptables