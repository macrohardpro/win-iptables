// rule_store.cpp -- RuleStore implementation (Task 6.2-6.5)
#include "winiptables/rule_store.hpp"
#include "winiptables/imatch.hpp"  // Full definition of IMatch, for Rule destructor use

#include <algorithm>
#include <cctype>
#include <functional>
#include <iterator>
#include <stdexcept>

namespace winiptables {

// ---------------------------------------------------------------------------
// Construction / Initialization
// ---------------------------------------------------------------------------

RuleStore::RuleStore() {
    init_builtin_tables();
}

void RuleStore::init_builtin_tables() {
    // filter table: INPUT / OUTPUT / FORWARD
    {
        Table t;
        t.kind = TableKind::kFilter;
        for (const char* name : {"INPUT", "OUTPUT", "FORWARD"}) {
            Chain c;
            c.name = name;
            c.policy = Target{Target::Kind::kAccept};
            t.chains.emplace(name, std::move(c));
        }
        tables_.emplace(TableKind::kFilter, std::move(t));
    }

    // nat table: PREROUTING / OUTPUT / POSTROUTING
    {
        Table t;
        t.kind = TableKind::kNat;
        for (const char* name : {"PREROUTING", "OUTPUT", "POSTROUTING"}) {
            Chain c;
            c.name = name;
            c.policy = Target{Target::Kind::kAccept};
            t.chains.emplace(name, std::move(c));
        }
        tables_.emplace(TableKind::kNat, std::move(t));
    }

    // mangle table: PREROUTING / INPUT / FORWARD / OUTPUT / POSTROUTING
    {
        Table t;
        t.kind = TableKind::kMangle;
        for (const char* name :
             {"PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"}) {
            Chain c;
            c.name = name;
            c.policy = Target{Target::Kind::kAccept};
            t.chains.emplace(name, std::move(c));
        }
        tables_.emplace(TableKind::kMangle, std::move(t));
    }
}

// ---------------------------------------------------------------------------
// Helpers: Table / Chain lookup
// ---------------------------------------------------------------------------

Table* RuleStore::get_table(TableKind kind) {
    auto it = tables_.find(kind);
    return (it != tables_.end()) ? &it->second : nullptr;
}

const Table* RuleStore::get_table(TableKind kind) const {
    auto it = tables_.find(kind);
    return (it != tables_.end()) ? &it->second : nullptr;
}

Chain* RuleStore::get_chain_locked(TableKind table, const std::string& name) {
    Table* t = get_table(table);
    if (!t) return nullptr;
    auto it = t->chains.find(name);
    return (it != t->chains.end()) ? &it->second : nullptr;
}

const Chain* RuleStore::get_chain_locked(TableKind table,
                                          const std::string& name) const {
    const Table* t = get_table(table);
    if (!t) return nullptr;
    auto it = t->chains.find(name);
    return (it != t->chains.end()) ? &it->second : nullptr;
}

// ---------------------------------------------------------------------------
// Chain name validation (max 29 characters, only letters/digits/hyphens/underscores)
// ---------------------------------------------------------------------------

bool RuleStore::is_valid_chain_name(const std::string& name) {
    if (name.empty() || name.size() > 29) return false;
    for (char c : name) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_')
            return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Built-in chain check (chains with policy are built-in chains)
// ---------------------------------------------------------------------------

static bool is_builtin_chain(const Chain& c) {
    return c.policy.has_value();
}

// ---------------------------------------------------------------------------
// Task 6.3: Chain management operations
// ---------------------------------------------------------------------------

// -N: Create user-defined chain
StoreResult RuleStore::create_chain(TableKind table, const std::string& chain_name) {
    if (!is_valid_chain_name(chain_name))
        return StoreResult::Err("Invalid chain name '" + chain_name + "'");

    std::unique_lock lock(mutex_);
    Table* t = get_table(table);
    if (!t) return StoreResult::Err("No such table");

    if (t->chains.count(chain_name))
        return StoreResult::Err("Chain already exists");

    Chain c;
    c.name = chain_name;
    // User-defined chains have no default policy
    t->chains.emplace(chain_name, std::move(c));
    return StoreResult::Ok();
}

// -X: Delete user-defined chain
StoreResult RuleStore::delete_chain(TableKind table, const std::string& chain_name) {
    std::unique_lock lock(mutex_);
    Table* t = get_table(table);
    if (!t) return StoreResult::Err("No such table");

    auto it = t->chains.find(chain_name);
    if (it == t->chains.end())
        return StoreResult::Err("No chain/target/match by that name");

    const Chain& c = it->second;
    if (is_builtin_chain(c))
        return StoreResult::Err("Cannot delete built-in chain");

    if (!c.rules.empty())
        return StoreResult::Err("Chain is not empty");

    if (is_chain_referenced(chain_name))
        return StoreResult::Err("Chain is referenced by other rules");

    t->chains.erase(it);
    return StoreResult::Ok();
}

// -P: Set built-in chain default policy
StoreResult RuleStore::set_policy(TableKind table, const std::string& chain_name,
                                   Target policy) {
    std::unique_lock lock(mutex_);
    Chain* c = get_chain_locked(table, chain_name);
    if (!c) return StoreResult::Err("No chain/target/match by that name");

    if (!is_builtin_chain(*c))
        return StoreResult::Err("Cannot set policy on user-defined chain");

    c->policy = std::move(policy);
    return StoreResult::Ok();
}

// -E: Rename user-defined chain
StoreResult RuleStore::rename_chain(TableKind table,
                                     const std::string& old_name,
                                     const std::string& new_name) {
    if (!is_valid_chain_name(new_name))
        return StoreResult::Err("Invalid chain name '" + new_name + "'");

    std::unique_lock lock(mutex_);
    Table* t = get_table(table);
    if (!t) return StoreResult::Err("No such table");

    auto it = t->chains.find(old_name);
    if (it == t->chains.end())
        return StoreResult::Err("No chain/target/match by that name");

    if (is_builtin_chain(it->second))
        return StoreResult::Err("Cannot rename built-in chain");

    if (t->chains.count(new_name))
        return StoreResult::Err("Chain already exists");

    // Move node and update name field
    Chain moved = std::move(it->second);
    moved.name  = new_name;
    t->chains.erase(it);
    t->chains.emplace(new_name, std::move(moved));
    return StoreResult::Ok();
}

// ---------------------------------------------------------------------------
// Task 6.4: Rule management operations
// ---------------------------------------------------------------------------

// -A: Append rule
StoreResult RuleStore::append_rule(TableKind table, const std::string& chain_name,
                                    Rule rule) {
    std::unique_lock lock(mutex_);
    Chain* c = get_chain_locked(table, chain_name);
    if (!c) return StoreResult::Err("No chain/target/match by that name");

    c->rules.push_back(std::make_unique<Rule>(std::move(rule)));
    return StoreResult::Ok();
}

// -I: Insert rule (rulenum starts from 1)
StoreResult RuleStore::insert_rule(TableKind table, const std::string& chain_name,
                                    Rule rule, int rulenum) {
    std::unique_lock lock(mutex_);
    Chain* c = get_chain_locked(table, chain_name);
    if (!c) return StoreResult::Err("No chain/target/match by that name");

    int sz = static_cast<int>(c->rules.size());
    if (rulenum < 1 || rulenum > sz + 1)
        return StoreResult::Err("Invalid rule number");

    auto pos = std::next(c->rules.begin(), rulenum - 1);
    c->rules.insert(pos, std::make_unique<Rule>(std::move(rule)));
    return StoreResult::Ok();
}

// -D <rulenum>: Delete rule by number
StoreResult RuleStore::delete_rule_by_num(TableKind table,
                                           const std::string& chain_name,
                                           int rulenum) {
    std::unique_lock lock(mutex_);
    Chain* c = get_chain_locked(table, chain_name);
    if (!c) return StoreResult::Err("No chain/target/match by that name");

    int sz = static_cast<int>(c->rules.size());
    if (rulenum < 1 || rulenum > sz)
        return StoreResult::Err("Invalid rule number");

    c->rules.erase(std::next(c->rules.begin(), rulenum - 1));
    return StoreResult::Ok();
}

// -D <rule-spec>: Delete first matching rule by specification
StoreResult RuleStore::delete_rule_by_spec(TableKind table,
                                            const std::string& chain_name,
                                            std::function<bool(const Rule&)> match_fn) {
    std::unique_lock lock(mutex_);
    Chain* c = get_chain_locked(table, chain_name);
    if (!c) return StoreResult::Err("No chain/target/match by that name");

    for (auto it = c->rules.begin(); it != c->rules.end(); ++it) {
        if (match_fn(**it)) {
            c->rules.erase(it);
            return StoreResult::Ok();
        }
    }
    return StoreResult::Err("Bad rule (does not exist)");
}

// -R: Replace rule
StoreResult RuleStore::replace_rule(TableKind table, const std::string& chain_name,
                                     int rulenum, Rule rule) {
    std::unique_lock lock(mutex_);
    Chain* c = get_chain_locked(table, chain_name);
    if (!c) return StoreResult::Err("No chain/target/match by that name");

    int sz = static_cast<int>(c->rules.size());
    if (rulenum < 1 || rulenum > sz)
        return StoreResult::Err("Invalid rule number");

    auto pos = std::next(c->rules.begin(), rulenum - 1);
    c->rules.erase(pos);
    c->rules.insert(std::next(c->rules.begin(), rulenum - 1),
                   std::make_unique<Rule>(std::move(rule)));
    return StoreResult::Ok();
}

// -L: List chains (shared lock for reading)
std::vector<const Chain*> RuleStore::list_chains(TableKind table) const {
    std::shared_lock lock(mutex_);
    const Table* t = get_table(table);
    if (!t) return {};

    std::vector<const Chain*> result;
    result.reserve(t->chains.size());
    for (const auto& [name, chain] : t->chains)
        result.push_back(&chain);
    return result;
}

// Get single chain (shared lock for reading)
const Chain* RuleStore::get_chain(TableKind table,
                                   const std::string& chain_name) const {
    std::shared_lock lock(mutex_);
    return get_chain_locked(table, chain_name);
}

// Cross-table chain lookup (used by rule engine for JUMP)
const Chain* RuleStore::get_chain_any_table(const std::string& chain_name) const {
    std::shared_lock lock(mutex_);
    for (const auto& [kind, tbl] : tables_) {
        auto it = tbl.chains.find(chain_name);
        if (it != tbl.chains.end()) return &it->second;
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// Task 6.5: Counter operations
// ---------------------------------------------------------------------------

// -Z: Zero counters
StoreResult RuleStore::zero_counters(TableKind table, const std::string& chain_name) {
    std::unique_lock lock(mutex_);
    Table* t = get_table(table);
    if (!t) return StoreResult::Err("No such table");

    auto zero_chain = [](Chain& c) {
        for (auto& rptr : c.rules)
            rptr->counters.Reset();
    };

    if (chain_name.empty()) {
        // Zero all chains in the entire table
        for (auto& [name, c] : t->chains)
            zero_chain(c);
    } else {
        Chain* c = get_chain_locked(table, chain_name);
        if (!c) return StoreResult::Err("No chain/target/match by that name");
        zero_chain(*c);
    }
    return StoreResult::Ok();
}

// ---------------------------------------------------------------------------
// Helper: Check if chain is referenced
// ---------------------------------------------------------------------------

bool RuleStore::is_chain_referenced(const std::string& chain_name) const {
    for (const auto& [kind, tbl] : tables_) {
        for (const auto& [cname, chain] : tbl.chains) {
            for (const auto& rptr : chain.rules) {
                if (rptr->target.kind == Target::Kind::kJump &&
                    rptr->target.jump_chain == chain_name) {
                    return true;
                }
            }
        }
    }
    return false;
}

}  // namespace winiptables