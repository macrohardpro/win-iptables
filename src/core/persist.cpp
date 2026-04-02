// persist.cpp — Rule persistence implementation (Task 11.2–11.5)
//
// Note: when load() parses "-A CHAIN <rule>", full match parsing depends on the CLI parser
// (Task 12). The current version stores the rule line as raw text (only parses the target).
// Full parsing will be integrated after the CLI parser is finished.

#include "winiptables/persist.hpp"
#include "winiptables/imatch.hpp"
#include "winiptables/rule_builder.hpp"

#include <algorithm>
#include <fstream>
#include <future>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace winiptables {

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// Map Target::Kind to string
static std::string target_kind_str(Target::Kind kind) {
    switch (kind) {
        case Target::Kind::kAccept:     return "ACCEPT";
        case Target::Kind::kDrop:       return "DROP";
        case Target::Kind::kReject:     return "REJECT";
        case Target::Kind::kReturn:     return "RETURN";
        case Target::Kind::kLog:        return "LOG";
        case Target::Kind::kJump:       return "";   // handled by caller
        case Target::Kind::kMasquerade: return "MASQUERADE";
        case Target::Kind::kDnat:       return "DNAT";
        case Target::Kind::kSnat:       return "SNAT";
        default:                        return "ACCEPT";
    }
}

// Map string to Target::Kind (used by load)
static bool parse_target_kind(const std::string& s, Target& out) {
    if (s == "ACCEPT")     { out.kind = Target::Kind::kAccept;     return true; }
    if (s == "DROP")       { out.kind = Target::Kind::kDrop;       return true; }
    if (s == "REJECT")     { out.kind = Target::Kind::kReject;     return true; }
    if (s == "RETURN")     { out.kind = Target::Kind::kReturn;     return true; }
    if (s == "LOG")        { out.kind = Target::Kind::kLog;        return true; }
    if (s == "MASQUERADE") { out.kind = Target::Kind::kMasquerade; return true; }
    if (s == "DNAT")       { out.kind = Target::Kind::kDnat;       return true; }
    if (s == "SNAT")       { out.kind = Target::Kind::kSnat;       return true; }
    // Otherwise treat as JUMP to a user-defined chain
    out.kind       = Target::Kind::kJump;
    out.jump_chain = s;
    return true;
}

// Map TableKind to iptables-save table name
static std::string table_kind_to_name(TableKind kind) {
    switch (kind) {
        case TableKind::kFilter: return "filter";
        case TableKind::kNat:    return "nat";
        case TableKind::kMangle: return "mangle";
        case TableKind::kRaw:    return "raw";
        default:                 return "filter";
    }
}

// Map iptables-save table name to TableKind
static bool table_name_to_kind(const std::string& name, TableKind& out) {
    if (name == "filter") { out = TableKind::kFilter; return true; }
    if (name == "nat")    { out = TableKind::kNat;    return true; }
    if (name == "mangle") { out = TableKind::kMangle; return true; }
    if (name == "raw")    { out = TableKind::kRaw;    return true; }
    return false;
}

// Emit tables in a fixed order (consistent with iptables-save convention)
static const TableKind kTableOrder[] = {
    TableKind::kFilter,
    TableKind::kNat,
    TableKind::kMangle,
};

// Built-in chain order (varies by table)
static std::vector<std::string> builtin_chain_order(TableKind kind) {
    switch (kind) {
        case TableKind::kFilter:
            return {"INPUT", "FORWARD", "OUTPUT"};
        case TableKind::kNat:
            return {"PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"};
        case TableKind::kMangle:
            return {"PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"};
        default:
            return {};
    }
}

// Serialize Target as "-j TARGET [args]"
std::string RulePersist::target_to_text(const Target& target) {
    if (target.kind == Target::Kind::kJump) {
        return "-j " + target.jump_chain;
    }
    if (target.kind == Target::Kind::kLog) {
        std::string s = "-j LOG";
        if (!target.log_prefix.empty())
            s += " --log-prefix \"" + target.log_prefix + "\"";
        if (target.log_level != 0)
            s += " --log-level " + std::to_string(target.log_level);
        return s;
    }
    if (target.kind == Target::Kind::kDnat && !target.to_addr.empty()) {
        return "-j DNAT --to-destination " + target.to_addr;
    }
    if (target.kind == Target::Kind::kSnat && !target.to_addr.empty()) {
        return "-j SNAT --to-source " + target.to_addr;
    }
    return "-j " + target_kind_str(target.kind);
}

// ---------------------------------------------------------------------------
// serialize_table — serialize a single table in iptables-save format
// ---------------------------------------------------------------------------

void RulePersist::serialize_table(const RuleStore& store, TableKind kind,
                                   const std::string& table_name,
                                   std::string& out) {
    // Get all chains in this table
    auto chains = store.list_chains(kind);
    if (chains.empty()) return;

    out += "*" + table_name + "\n";

    // Emit built-in chain policy lines first, then user-defined chains
    auto builtin_order = builtin_chain_order(kind);

    // Emit built-in chain policy lines
    for (const auto& bname : builtin_order) {
        for (const Chain* c : chains) {
            if (c->name != bname) continue;
            std::string policy_str = "-";
            if (c->policy.has_value()) {
                policy_str = target_kind_str(c->policy->kind);
            }
            out += ":" + c->name + " " + policy_str + " [0:0]\n";
        }
    }

    // Emit user-defined chain policy lines (policy is "-")
    for (const Chain* c : chains) {
        bool is_builtin = false;
        for (const auto& bname : builtin_order) {
            if (c->name == bname) { is_builtin = true; break; }
        }
        if (!is_builtin) {
            out += ":" + c->name + " - [0:0]\n";
        }
    }

    // Emit rules: built-in chains first, then user-defined chains
    auto emit_rules = [&](const Chain* c) {
        for (const auto& rptr : c->rules) {
            const Rule& rule = *rptr;
            std::string rule_line = "-A " + c->name;
            // Serialize each match
            for (const auto& m : rule.matches) {
                rule_line += " " + m->ToRuleText();
            }
            // Serialize target
            rule_line += " " + target_to_text(rule.target);
            out += rule_line + "\n";
        }
    };

    for (const auto& bname : builtin_order) {
        for (const Chain* c : chains) {
            if (c->name == bname) { emit_rules(c); break; }
        }
    }
    for (const Chain* c : chains) {
        bool is_builtin = false;
        for (const auto& bname : builtin_order) {
            if (c->name == bname) { is_builtin = true; break; }
        }
        if (!is_builtin) emit_rules(c);
    }

    out += "COMMIT\n";
}

// ---------------------------------------------------------------------------
// save() — synchronous save (Task 11.2)
// ---------------------------------------------------------------------------

bool RulePersist::save(const RuleStore& store, const std::string& path) {
    std::string content;
    content += "# Generated by winiptables\n";

    for (TableKind kind : kTableOrder) {
        serialize_table(store, kind, table_kind_to_name(kind), content);
    }

    std::ofstream ofs(path, std::ios::out | std::ios::trunc);
    if (!ofs.is_open()) {
        std::cerr << "winiptables: cannot open file for writing: " << path << "\n";
        return false;
    }
    ofs << content;
    if (!ofs.good()) {
        std::cerr << "winiptables: write error: " << path << "\n";
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// load() — synchronous load (Task 11.3 / 11.4)
// ---------------------------------------------------------------------------
//
// Simplified parsing: for "-A CHAIN <rule>" lines, match conditions are not parsed yet
// (only -j TARGET is parsed). Full match parsing will be integrated after the CLI parser
// (Task 12) is finished.

// Helper: split by whitespace
static std::vector<std::string> split_tokens(const std::string& s) {
    std::vector<std::string> tokens;
    std::istringstream iss(s);
    std::string tok;
    while (iss >> tok) tokens.push_back(tok);
    return tokens;
}

// Helper: trim leading/trailing whitespace
static std::string trim(const std::string& s) {
    const auto b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    const auto e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

bool RulePersist::load(RuleStore& store, const std::string& path, bool noflush) {
    std::ifstream ifs(path);
    if (!ifs.is_open()) {
        std::cerr << "winiptables: cannot open file: " << path << "\n";
        return false;
    }

    std::string line;
    int line_no = 0;
    TableKind current_table = TableKind::kFilter;
    bool in_table = false;

    // Track which tables were flushed during this load (noflush=false: flush each table once)
    std::vector<TableKind> flushed_tables;

    auto error = [&](const std::string& msg) -> bool {
        std::cerr << "Error at line " << line_no << ": " << msg << "\n";
        return false;
    };

    while (std::getline(ifs, line)) {
        ++line_no;
        std::string trimmed = trim(line);

        // Skip blank lines
        if (trimmed.empty()) continue;

        // Skip comment lines
        if (trimmed[0] == '#') continue;

        // *table line
        if (trimmed[0] == '*') {
            std::string tname = trim(trimmed.substr(1));
            if (!table_name_to_kind(tname, current_table)) {
                return error("Unknown table '" + tname + "'");
            }
            in_table = true;

            // noflush=false: flush this table (once per table)
            if (!noflush) {
                bool already = false;
                for (auto k : flushed_tables) {
                    if (k == current_table) { already = true; break; }
                }
                if (!already) {
                    // Clear rules from all chains in this table
                    auto chains = store.list_chains(current_table);
                    for (const Chain* c : chains) {
                        // Delete one-by-one (from back to front)
                        int sz = static_cast<int>(c->rules.size());
                        for (int i = sz; i >= 1; --i) {
                            store.delete_rule_by_num(current_table, c->name, 1);
                        }
                    }
                    flushed_tables.push_back(current_table);
                }
            }
            continue;
        }

        // COMMIT line
        if (trimmed == "COMMIT") {
            in_table = false;
            continue;
        }

        // :CHAIN POLICY [pkts:bytes] line
        if (trimmed[0] == ':') {
            if (!in_table) return error("':' line outside of table block");
            auto tokens = split_tokens(trimmed.substr(1));
            if (tokens.size() < 2) {
                return error("Malformed chain header: " + trimmed);
            }
            const std::string& chain_name = tokens[0];
            const std::string& policy_str = tokens[1];

            // Create chain if it doesn't exist (user-defined chain)
            const Chain* existing = store.get_chain(current_table, chain_name);
            if (!existing) {
                auto res = store.create_chain(current_table, chain_name);
                if (!res) {
                    return error("Cannot create chain '" + chain_name + "': " + res.message);
                }
            }

            // Set policy (built-in chains have a policy; "-" means no policy for user-defined chains)
            if (policy_str != "-") {
                Target policy;
                if (!parse_target_kind(policy_str, policy)) {
                    return error("Unknown policy '" + policy_str + "'");
                }
                // Only built-in chains accept policies (ignore failure for user-defined chains)
                store.set_policy(current_table, chain_name, policy);
            }
            continue;
        }

        // -A CHAIN <rule> line
        if (trimmed.size() >= 3 && trimmed[0] == '-' && trimmed[1] == 'A') {
            if (!in_table) return error("'-A' line outside of table block");
            auto tokens = split_tokens(trimmed);
            // tokens[0]="-A", tokens[1]=chain_name, tokens[2..]=rule args
            if (tokens.size() < 2) {
                return error("Malformed rule line: " + trimmed);
            }
            const std::string& chain_name = tokens[1];

            // Build rule with full match parsing via BuildRule
            std::vector<std::string> rule_args(tokens.begin() + 2, tokens.end());
            std::string err;
            Rule rule = BuildRule(rule_args, err);
            if (!err.empty()) {
                return error("Cannot parse rule '" + trimmed + "': " + err);
            }

            auto res = store.append_rule(current_table, chain_name, std::move(rule));
            if (!res) {
                return error("Cannot append rule to chain '" + chain_name +
                             "': " + res.message);
            }
            continue;
        }

        // Unrecognized line
        return error("Unrecognized line: " + trimmed);
    }

    return true;
}

// ---------------------------------------------------------------------------
// save_async() — async save (Task 11.5)
// ---------------------------------------------------------------------------

std::future<bool> RulePersist::save_async(const RuleStore& store,
                                           const std::string& path) {
    // Serialize synchronously, then write in a background thread to avoid a dangling store reference
    std::string content;
    content += "# Generated by winiptables\n";
    for (TableKind kind : kTableOrder) {
        serialize_table(store, kind, table_kind_to_name(kind), content);
    }

    return std::async(std::launch::async, [content = std::move(content), path]() {
        std::ofstream ofs(path, std::ios::out | std::ios::trunc);
        if (!ofs.is_open()) {
            std::cerr << "winiptables: cannot open file for writing: " << path << "\n";
            return false;
        }
        ofs << content;
        if (!ofs.good()) {
            std::cerr << "winiptables: write error: " << path << "\n";
            return false;
        }
        return true;
    });
}

}  // namespace winiptables
