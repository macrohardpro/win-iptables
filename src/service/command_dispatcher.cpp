// command_dispatcher.cpp — Command dispatch (Task 13.4)
// Routes parsed iptables commands to the corresponding RuleStore operations

#include "command_dispatcher.hpp"

#include "winiptables/imatch.hpp"
#include "winiptables/log.hpp"
#include "winiptables/matches/basic.hpp"
#include "winiptables/matches/tcp.hpp"
#include "winiptables/matches/multiport.hpp"
#include "winiptables/matches/state.hpp"
#include "winiptables/persist.hpp"
#include "winiptables/rule_builder.hpp"

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

namespace winiptables {

// -----------------------------------------------------------------------
// Constructor
// -----------------------------------------------------------------------

CommandDispatcher::CommandDispatcher(RuleStore& store)
    : store_(store) {}

// -----------------------------------------------------------------------
// Helper: parse table name
// -----------------------------------------------------------------------

TableKind CommandDispatcher::parse_table(const std::string& name) {
    if (name == "filter") return TableKind::kFilter;
    if (name == "nat")    return TableKind::kNat;
    if (name == "mangle") return TableKind::kMangle;
    if (name == "raw")    return TableKind::kRaw;
    return TableKind::kFilter;  // default
}

// -----------------------------------------------------------------------
// Helper: parse target string
// -----------------------------------------------------------------------

Target CommandDispatcher::parse_target(const std::string& target_str) {
    Target t;
    if (target_str == "ACCEPT")     { t.kind = Target::Kind::kAccept; }
    else if (target_str == "DROP")  { t.kind = Target::Kind::kDrop; }
    else if (target_str == "RETURN"){ t.kind = Target::Kind::kReturn; }
    else if (target_str == "REJECT"){ t.kind = Target::Kind::kReject; }
    else if (target_str == "LOG")   { t.kind = Target::Kind::kLog; }
    else if (target_str == "MASQUERADE") { t.kind = Target::Kind::kMasquerade; }
    else if (target_str == "DNAT")  { t.kind = Target::Kind::kDnat; }
    else if (target_str == "SNAT")  { t.kind = Target::Kind::kSnat; }
    else {
        // User-defined chain jump
        t.kind = Target::Kind::kJump;
        t.jump_chain = target_str;
    }
    return t;
}

// -----------------------------------------------------------------------
// Helper: build a Rule from rule_args — delegates to shared BuildRule()
// -----------------------------------------------------------------------

Rule CommandDispatcher::build_rule(const std::vector<std::string>& rule_args,
                                    std::string& err) {
    return BuildRule(rule_args, err);
}

// -----------------------------------------------------------------------
// Helper: format chain rule list
// -----------------------------------------------------------------------

void CommandDispatcher::format_chain_list(TableKind table,
                                           const std::string& chain_name,
                                           bool /*numeric*/,
                                           bool verbose,
                                           bool line_numbers,
                                           std::string& out) const {
    auto chains = store_.list_chains(table);
    for (const Chain* chain : chains) {
        if (!chain_name.empty() && chain->name != chain_name) continue;

        // Chain header
        out += "Chain " + chain->name;
        if (chain->policy.has_value()) {
            const Target& pol = *chain->policy;
            std::string pol_str;
            switch (pol.kind) {
                case Target::Kind::kAccept: pol_str = "ACCEPT"; break;
                case Target::Kind::kDrop:   pol_str = "DROP";   break;
                default:                    pol_str = "ACCEPT"; break;
            }
            out += " (policy " + pol_str + ")";
        } else {
            out += " (0 references)";
        }
        out += "\n";

        // Column header
        if (verbose) {
            out += "pkts bytes target     prot opt in     out     source               destination\n";
        } else {
            out += "target     prot opt source               destination\n";
        }

        // Rule list
        int num = 1;
        for (const auto& rule_ptr : chain->rules) {
            if (!rule_ptr) { ++num; continue; }
            out += format_rule(*rule_ptr, num, false, verbose, line_numbers);
            out += "\n";
            ++num;
        }
    }
}

std::string CommandDispatcher::format_rule(const Rule& rule, int num,
                                            bool /*numeric*/, bool verbose,
                                            bool line_numbers) {
    // ── Extract fields for each column ───────────────────────────────────────
    std::string col_prot   = "all";
    std::string col_in     = "*";
    std::string col_out    = "*";
    std::string col_src    = "0.0.0.0/0";
    std::string col_dst    = "0.0.0.0/0";
    std::vector<std::string> extra_opts;  // match conditions not part of fixed columns

    auto ip_to_str = [](uint32_t network_be, uint8_t prefix_len) -> std::string {
        char buf[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &network_be, buf, sizeof(buf));
        if (prefix_len == 32) return buf;
        return std::string(buf) + "/" + std::to_string(prefix_len);
    };

    for (const auto& m : rule.matches) {
        if (!m) continue;
        if (auto* pm = dynamic_cast<const ProtocolMatch*>(m.get())) {
            // Extract protocol name from ToRuleText() (strip "-p " prefix)
            std::string t = pm->ToRuleText();
            auto pos = t.rfind(' ');
            col_prot = (pos != std::string::npos) ? t.substr(pos + 1) : t;
        } else if (auto* sm = dynamic_cast<const SrcIpMatch*>(m.get())) {
            std::string t = sm->ToRuleText();  // "-s x.x.x.x/n"
            auto pos = t.rfind(' ');
            col_src = (pos != std::string::npos) ? t.substr(pos + 1) : t;
        } else if (auto* dm = dynamic_cast<const DstIpMatch*>(m.get())) {
            std::string t = dm->ToRuleText();
            auto pos = t.rfind(' ');
            col_dst = (pos != std::string::npos) ? t.substr(pos + 1) : t;
        } else if (dynamic_cast<const InIfaceMatch*>(m.get())) {
            // Interface name is currently reported as "*" (we only store an index today)
            col_in = "*";
        } else if (dynamic_cast<const OutIfaceMatch*>(m.get())) {
            col_out = "*";
        } else {
            // DstPortMatch / SrcPortMatch / TcpFlagsMatch / IcmpTypeMatch, etc.
            // Convert to a short iptables-style representation
            std::string t = m->ToRuleText();
            // --dport 80  →  tcp dpt:80
            // --sport 80  →  tcp spt:80
            // --dport 80:443 → tcp dpts:80:443
            auto replace_opt = [&](const std::string& from, const std::string& to) {
                auto p = t.find(from);
                if (p != std::string::npos) {
                    t.replace(p, from.size(), to);
                    return true;
                }
                return false;
            };
            if (!replace_opt("--dport ", "tcp dpt:") &&
                !replace_opt("--sport ", "tcp spt:") &&
                !replace_opt("--tcp-flags ", "tcp flags:") &&
                !replace_opt("--icmp-type ", "icmp type ")) {
                // Keep other extension modules as-is
            }
            extra_opts.push_back(t);
        }
    }

    // ── Target string ────────────────────────────────────────────────────────
    std::string target_str;
    std::string target_extra;  // appended after the fixed columns (e.g. "to:ip:port")
    switch (rule.target.kind) {
        case Target::Kind::kAccept:     target_str = "ACCEPT";     break;
        case Target::Kind::kDrop:       target_str = "DROP";       break;
        case Target::Kind::kReject:     target_str = "REJECT";     break;
        case Target::Kind::kReturn:     target_str = "RETURN";     break;
        case Target::Kind::kLog:        target_str = "LOG";        break;
        case Target::Kind::kJump:       target_str = rule.target.jump_chain; break;
        case Target::Kind::kMasquerade: target_str = "MASQUERADE"; break;
        case Target::Kind::kDnat:
            target_str = "DNAT";
            if (!rule.target.to_addr.empty())
                target_extra = "to:" + rule.target.to_addr;
            break;
        case Target::Kind::kSnat:
            target_str = "SNAT";
            if (!rule.target.to_addr.empty())
                target_extra = "to:" + rule.target.to_addr;
            break;
        default:                        target_str = "ACCEPT";     break;
    }

    // ── Format output ────────────────────────────────────────────────────────
    std::ostringstream oss;

    if (verbose) {
        uint64_t pkts  = rule.counters.packets.load(std::memory_order_relaxed);
        uint64_t bytes = rule.counters.bytes.load(std::memory_order_relaxed);

        if (line_numbers) {
            oss << std::setw(3) << num << "  ";
        }
        // pkts bytes target prot opt in out source destination [extra] [match opts]
        oss << std::setw(5) << pkts
            << " "
            << std::setw(5) << bytes
            << " "
            << std::left << std::setw(10) << target_str
            << std::setw(5)  << col_prot
            << std::setw(4)  << "--"
            << std::setw(7)  << col_in
            << std::setw(8)  << col_out
            << std::setw(21) << col_src
            << std::setw(21) << col_dst;
        for (const auto& opt : extra_opts) oss << " " << opt;
        if (!target_extra.empty()) oss << " " << target_extra;
    } else {
        if (line_numbers) {
            oss << std::setw(3) << num << "  ";
        }
        // target prot opt source destination [extra] [match opts]
        oss << std::left
            << std::setw(10) << target_str
            << std::setw(5)  << col_prot
            << std::setw(4)  << "--"
            << std::setw(21) << col_src
            << std::setw(21) << col_dst;
        for (const auto& opt : extra_opts) oss << " " << opt;
        if (!target_extra.empty()) oss << " " << target_extra;
    }

    return oss.str();
}

// -----------------------------------------------------------------------
// dispatch — main dispatcher entrypoint
// -----------------------------------------------------------------------

int CommandDispatcher::dispatch(const std::vector<std::string>& argv,
                                 std::string& stdout_out,
                                 std::string& stderr_out) {
    if (argv.empty()) {
        stderr_out = "Empty command";
        return 1;
    }

    // Parse argv in an argc/argv-style manner
    // Uses a simple internal parser (does not depend on the CLI parser)
    std::string table_name = "filter";
    std::string verb;
    std::string chain_name;
    int rule_num = 0;
    std::vector<std::string> rule_args;
    bool numeric = false, verbose = false, line_numbers = false;
    bool is_save = false, is_restore = false, noflush = false;
    std::string file_path;

    // Parse arguments
    for (size_t i = 0; i < argv.size(); ++i) {
        const std::string& arg = argv[i];

        if ((arg == "-t" || arg == "--table") && i + 1 < argv.size()) {
            table_name = argv[++i];
            continue;
        }
        if (arg == "-n" || arg == "--numeric") { numeric = true; continue; }
        if (arg == "-v" || arg == "--verbose") { verbose = true; continue; }
        if (arg == "--line-numbers") { line_numbers = true; continue; }
        if (arg == "--noflush") { noflush = true; continue; }

        if (verb.empty()) {
            auto is_num = [](const std::string& s) {
                return !s.empty() && std::all_of(s.begin(), s.end(), ::isdigit);
            };

            if (arg == "-A" || arg == "--append") {
                verb = "-A";
                if (i + 1 < argv.size() && argv[i+1][0] != '-') chain_name = argv[++i];
                continue;
            }
            if (arg == "-I" || arg == "--insert") {
                verb = "-I";
                if (i + 1 < argv.size() && argv[i+1][0] != '-') {
                    chain_name = argv[++i];
                    if (i + 1 < argv.size() && is_num(argv[i+1])) rule_num = std::stoi(argv[++i]);
                    else rule_num = 1;
                }
                continue;
            }
            if (arg == "-D" || arg == "--delete") {
                verb = "-D";
                if (i + 1 < argv.size() && argv[i+1][0] != '-') {
                    chain_name = argv[++i];
                    if (i + 1 < argv.size() && is_num(argv[i+1])) rule_num = std::stoi(argv[++i]);
                }
                continue;
            }
            if (arg == "-R" || arg == "--replace") {
                verb = "-R";
                if (i + 1 < argv.size() && argv[i+1][0] != '-') {
                    chain_name = argv[++i];
                    if (i + 1 < argv.size() && is_num(argv[i+1])) rule_num = std::stoi(argv[++i]);
                }
                continue;
            }
            if (arg == "-L" || arg == "--list") {
                verb = "-L";
                if (i + 1 < argv.size() && argv[i+1][0] != '-') chain_name = argv[++i];
                continue;
            }
            if (arg == "-S" || arg == "--list-rules") {
                verb = "-S"; continue;
            }
            if (arg == "-F" || arg == "--flush") {
                verb = "-F";
                if (i + 1 < argv.size() && argv[i+1][0] != '-') chain_name = argv[++i];
                continue;
            }
            if (arg == "-Z" || arg == "--zero") {
                verb = "-Z";
                if (i + 1 < argv.size() && argv[i+1][0] != '-') chain_name = argv[++i];
                continue;
            }
            if (arg == "-N" || arg == "--new-chain") {
                verb = "-N";
                if (i + 1 < argv.size()) chain_name = argv[++i];
                continue;
            }
            if (arg == "-X" || arg == "--delete-chain") {
                verb = "-X";
                if (i + 1 < argv.size() && argv[i+1][0] != '-') chain_name = argv[++i];
                continue;
            }
            if (arg == "-P" || arg == "--policy") {
                verb = "-P";
                if (i + 1 < argv.size()) chain_name = argv[++i];
                if (i + 1 < argv.size()) rule_args.push_back(argv[++i]);
                continue;
            }
            if (arg == "-E" || arg == "--rename-chain") {
                verb = "-E";
                if (i + 1 < argv.size()) chain_name = argv[++i];
                if (i + 1 < argv.size()) rule_args.push_back(argv[++i]);
                continue;
            }
            if (arg == "save") { is_save = true; verb = "save"; continue; }
            if (arg == "restore") { is_restore = true; verb = "restore"; continue; }
        } else {
            rule_args.push_back(arg);
        }
    }

    if (verb.empty()) verb = "-L";

    TableKind table = parse_table(table_name);

    LOG_DEBUG("dispatch: verb={} table={} chain={}", verb, table_name, chain_name);

    // ── Execute command ──────────────────────────────────────────────────────

    // -L: list rules
    if (verb == "-L") {
        format_chain_list(table, chain_name, numeric, verbose, line_numbers, stdout_out);
        return 0;
    }

    // -N: create chain
    if (verb == "-N") {
        auto res = store_.create_chain(table, chain_name);
        if (!res) { stderr_out = res.message; return 1; }
        return 0;
    }

    // -X: delete chain
    if (verb == "-X") {
        auto res = store_.delete_chain(table, chain_name);
        if (!res) { stderr_out = res.message; return 1; }
        return 0;
    }

    // -P: set policy
    if (verb == "-P") {
        if (rule_args.empty()) { stderr_out = "-P requires a policy target"; return 1; }
        Target pol = parse_target(rule_args[0]);
        auto res = store_.set_policy(table, chain_name, pol);
        if (!res) { stderr_out = res.message; return 1; }
        return 0;
    }

    // -E: rename chain
    if (verb == "-E") {
        if (rule_args.empty()) { stderr_out = "-E requires a new chain name"; return 1; }
        auto res = store_.rename_chain(table, chain_name, rule_args[0]);
        if (!res) { stderr_out = res.message; return 1; }
        return 0;
    }

    // -F: flush chain
    if (verb == "-F") {
        // Flush a specific chain or all chains
        if (chain_name.empty()) {
            bool again = true;
            while (again) {
                again = false;
                auto ch = store_.list_chains(table);
                for (const Chain* cc : ch) {
                    if (!cc->rules.empty()) {
                        store_.delete_rule_by_num(table, cc->name, 1);
                        again = true;
                        break;
                    }
                }
            }
        } else {
            bool again = true;
            while (again) {
                again = false;
                const Chain* ch = store_.get_chain(table, chain_name);
                if (ch && !ch->rules.empty()) {
                    store_.delete_rule_by_num(table, chain_name, 1);
                    again = true;
                }
            }
        }
        return 0;
    }

    // -Z: zero counters
    if (verb == "-Z") {
        auto res = store_.zero_counters(table, chain_name);
        if (!res) { stderr_out = res.message; return 1; }
        return 0;
    }

    // -A: append rule
    if (verb == "-A") {
        std::string err;
        Rule rule = build_rule(rule_args, err);
        if (!err.empty()) { LOG_ERROR("dispatch -A: {}", err); stderr_out = err; return 1; }
        auto res = store_.append_rule(table, chain_name, std::move(rule));
        if (!res) { LOG_ERROR("dispatch -A: {}", res.message); stderr_out = res.message; return 1; }
        LOG_INFO("Rule appended to {}/{}", table_name, chain_name);
        return 0;
    }

    // -I: insert rule
    if (verb == "-I") {
        std::string err;
        Rule rule = build_rule(rule_args, err);
        if (!err.empty()) { LOG_ERROR("dispatch -I: {}", err); stderr_out = err; return 1; }
        auto res = store_.insert_rule(table, chain_name, std::move(rule), rule_num);
        if (!res) { LOG_ERROR("dispatch -I: {}", res.message); stderr_out = res.message; return 1; }
        LOG_INFO("Rule inserted into {}/{} at position {}", table_name, chain_name, rule_num);
        return 0;
    }

    // -D: delete rule
    if (verb == "-D") {
        StoreResult res{};
        if (rule_num > 0) {
            res = store_.delete_rule_by_num(table, chain_name, rule_num);
        } else if (!rule_args.empty()) {
            // Delete by rule spec (simplified: not supported)
            stderr_out = "Deleting by rule spec is not supported; use a rule number";
            return 1;
        } else {
            stderr_out = "-D requires a rule number or a rule spec";
            return 1;
        }
        if (!res) { LOG_ERROR("dispatch -D: {}", res.message); stderr_out = res.message; return 1; }
        LOG_INFO("Rule {} deleted from {}/{}", rule_num, table_name, chain_name);
        return 0;
    }

    // -R: replace rule
    if (verb == "-R") {
        std::string err;
        Rule rule = build_rule(rule_args, err);
        if (!err.empty()) { LOG_ERROR("dispatch -R: {}", err); stderr_out = err; return 1; }
        auto res = store_.replace_rule(table, chain_name, rule_num, std::move(rule));
        if (!res) { LOG_ERROR("dispatch -R: {}", res.message); stderr_out = res.message; return 1; }
        LOG_INFO("Rule {} replaced in {}/{}", rule_num, table_name, chain_name);
        return 0;
    }

    // save: persist rules
    if (verb == "save") {
        std::string path = file_path.empty() ? "rules.v4" : file_path;
        LOG_INFO("Saving rules to {}", path);
        if (!RulePersist::save(store_, path)) {
            LOG_ERROR("Failed to save rules to {}", path);
            stderr_out = "Failed to save rules: " + path;
            return 1;
        }
        LOG_INFO("Rules saved to {}", path);
        return 0;
    }

    // restore: load rules
    if (verb == "restore") {
        std::string path = file_path.empty() ? "rules.v4" : file_path;
        LOG_INFO("Restoring rules from {}", path);
        if (!RulePersist::load(store_, path, noflush)) {
            LOG_ERROR("Failed to restore rules from {}", path);
            stderr_out = "Failed to load rules: " + path;
            return 1;
        }
        LOG_INFO("Rules restored from {}", path);
        return 0;
    }

    LOG_ERROR("Unknown command: {}", verb);
    stderr_out = "Unknown command: " + verb;
    return 1;
}

}  // namespace winiptables
