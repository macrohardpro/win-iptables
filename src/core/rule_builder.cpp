// rule_builder.cpp -- Shared rule argument parser

#include "winiptables/rule_builder.hpp"
#include "winiptables/imatch.hpp"
#include "winiptables/matches/basic.hpp"
#include "winiptables/matches/tcp.hpp"
#include "winiptables/matches/multiport.hpp"
#include "winiptables/matches/state.hpp"

#include <string>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

namespace winiptables {

// -----------------------------------------------------------------------
// Internal helpers
// -----------------------------------------------------------------------

static uint8_t ParseProtocol(const std::string& proto) {
    if (proto == "tcp")  return 6;
    if (proto == "udp")  return 17;
    if (proto == "icmp") return 1;
    if (proto == "all" || proto == "0") return 0;
    try { return static_cast<uint8_t>(std::stoi(proto)); } catch (...) {}
    return 0;
}

static std::pair<uint16_t, uint16_t> ParsePortRange(const std::string& s) {
    auto colon = s.find(':');
    if (colon == std::string::npos) {
        try {
            uint16_t p = static_cast<uint16_t>(std::stoi(s));
            return {p, p};
        } catch (...) { return {0, 0}; }
    }
    try {
        uint16_t lo = static_cast<uint16_t>(std::stoi(s.substr(0, colon)));
        uint16_t hi = static_cast<uint16_t>(std::stoi(s.substr(colon + 1)));
        return {lo, hi};
    } catch (...) { return {0, 0}; }
}

static Target ParseTarget(const std::string& s) {
    Target t;
    if (s == "ACCEPT")     { t.kind = Target::Kind::kAccept;     return t; }
    if (s == "DROP")       { t.kind = Target::Kind::kDrop;       return t; }
    if (s == "RETURN")     { t.kind = Target::Kind::kReturn;     return t; }
    if (s == "REJECT")     { t.kind = Target::Kind::kReject;     return t; }
    if (s == "LOG")        { t.kind = Target::Kind::kLog;        return t; }
    if (s == "MASQUERADE") { t.kind = Target::Kind::kMasquerade; return t; }
    if (s == "DNAT")       { t.kind = Target::Kind::kDnat;       return t; }
    if (s == "SNAT")       { t.kind = Target::Kind::kSnat;       return t; }
    // User-defined chain jump
    t.kind = Target::Kind::kJump;
    t.jump_chain = s;
    return t;
}

// -----------------------------------------------------------------------
// BuildRule
// -----------------------------------------------------------------------

Rule BuildRule(const std::vector<std::string>& rule_args, std::string& err) {
    Rule rule;
    Target target;
    bool has_target = false;
    bool next_negated = false;  // set by a standalone "!" token

    for (size_t i = 0; i < rule_args.size(); ++i) {
        const std::string& arg = rule_args[i];

        // Standalone "!" before an option: "! -p tcp"
        if (arg == "!") {
            next_negated = true;
            continue;
        }

        // Consume the pending negation flag for this token
        bool negated = next_negated;
        next_negated = false;

        // ── Target ──────────────────────────────────────────────────────────
        if (arg == "-j" || arg == "--jump") {
            if (i + 1 >= rule_args.size()) { err = "-j requires an argument"; return rule; }
            target = ParseTarget(rule_args[++i]);
            has_target = true;
            continue;
        }

        // LOG options (must come after -j LOG)
        if (arg == "--log-prefix" && has_target && target.kind == Target::Kind::kLog) {
            if (i + 1 < rule_args.size()) target.log_prefix = rule_args[++i];
            continue;
        }
        if (arg == "--log-level" && has_target && target.kind == Target::Kind::kLog) {
            if (i + 1 < rule_args.size()) {
                try { target.log_level = static_cast<uint8_t>(std::stoi(rule_args[++i])); }
                catch (...) {}
            }
            continue;
        }

        // REJECT --reject-with
        if (arg == "--reject-with" && has_target && target.kind == Target::Kind::kReject) {
            if (i + 1 < rule_args.size()) ++i;
            continue;
        }

        // DNAT/SNAT --to-destination / --to-source / --to
        if (arg == "--to-destination" || arg == "--to-source" || arg == "--to") {
            if (i + 1 < rule_args.size() && has_target) {
                target.to_addr = rule_args[++i];
            }
            continue;
        }

        // ── Match conditions ─────────────────────────────────────────────────

        // -p protocol  (also supports "-p ! tcp" inline negation)
        if (arg == "-p" || arg == "--protocol") {
            if (i + 1 >= rule_args.size()) { err = "-p requires an argument"; return rule; }
            std::string proto = rule_args[++i];
            if (proto == "!") { negated = !negated; if (i + 1 < rule_args.size()) proto = rule_args[++i]; }
            rule.matches.push_back(std::make_unique<ProtocolMatch>(ParseProtocol(proto), negated));
            continue;
        }

        // -s source IP/CIDR
        if (arg == "-s" || arg == "--source") {
            if (i + 1 >= rule_args.size()) { err = "-s requires an argument"; return rule; }
            std::string cidr = rule_args[++i];
            if (cidr == "!") { negated = !negated; if (i + 1 < rule_args.size()) cidr = rule_args[++i]; }
            try {
                auto r = ParseCidr(cidr);
                rule.matches.push_back(std::make_unique<SrcIpMatch>(r.network_be, r.prefix_len, negated));
            } catch (...) { err = "Invalid source IP: " + cidr; return rule; }
            continue;
        }

        // -d destination IP/CIDR
        if (arg == "-d" || arg == "--destination") {
            if (i + 1 >= rule_args.size()) { err = "-d requires an argument"; return rule; }
            std::string cidr = rule_args[++i];
            if (cidr == "!") { negated = !negated; if (i + 1 < rule_args.size()) cidr = rule_args[++i]; }
            try {
                auto r = ParseCidr(cidr);
                rule.matches.push_back(std::make_unique<DstIpMatch>(r.network_be, r.prefix_len, negated));
            } catch (...) { err = "Invalid destination IP: " + cidr; return rule; }
            continue;
        }

        // -i in-interface
        if (arg == "-i" || arg == "--in-interface") {
            if (i + 1 >= rule_args.size()) { err = "-i requires an argument"; return rule; }
            std::string iface = rule_args[++i];
            if (iface == "!") { negated = !negated; if (i + 1 < rule_args.size()) iface = rule_args[++i]; }
            rule.matches.push_back(std::make_unique<InIfaceMatch>(0, negated));
            continue;
        }

        // -o out-interface
        if (arg == "-o" || arg == "--out-interface") {
            if (i + 1 >= rule_args.size()) { err = "-o requires an argument"; return rule; }
            std::string iface = rule_args[++i];
            if (iface == "!") { negated = !negated; if (i + 1 < rule_args.size()) iface = rule_args[++i]; }
            rule.matches.push_back(std::make_unique<OutIfaceMatch>(0, negated));
            continue;
        }

        // --dport destination port
        if (arg == "--dport" || arg == "--destination-port") {
            if (i + 1 >= rule_args.size()) { err = "--dport requires an argument"; return rule; }
            std::string port = rule_args[++i];
            if (port == "!") { negated = !negated; if (i + 1 < rule_args.size()) port = rule_args[++i]; }
            auto [lo, hi] = ParsePortRange(port);
            rule.matches.push_back(std::make_unique<DstPortMatch>(lo, hi, negated));
            continue;
        }

        // --sport source port
        if (arg == "--sport" || arg == "--source-port") {
            if (i + 1 >= rule_args.size()) { err = "--sport requires an argument"; return rule; }
            std::string port = rule_args[++i];
            if (port == "!") { negated = !negated; if (i + 1 < rule_args.size()) port = rule_args[++i]; }
            auto [lo, hi] = ParsePortRange(port);
            rule.matches.push_back(std::make_unique<SrcPortMatch>(lo, hi, negated));
            continue;
        }

        // -m match extension (consume module name; options follow as separate tokens)
        if (arg == "-m" || arg == "--match") {
            if (i + 1 < rule_args.size()) ++i;
            continue;
        }

        // --tcp-flags <mask> <comp>
        if (arg == "--tcp-flags") {
            if (i + 2 >= rule_args.size()) { err = "--tcp-flags requires two arguments"; return rule; }
            std::string mask_str = rule_args[++i];
            if (mask_str == "!") { negated = !negated; if (i + 2 >= rule_args.size()) { err = "--tcp-flags requires two arguments"; return rule; } mask_str = rule_args[++i]; }
            const std::string& comp_str = rule_args[++i];
            try {
                uint8_t mask = TcpFlagsMatch::ParseFlags(mask_str);
                uint8_t comp = TcpFlagsMatch::ParseFlags(comp_str);
                rule.matches.push_back(std::make_unique<TcpFlagsMatch>(mask, comp, negated));
            } catch (const std::exception& e) { err = e.what(); return rule; }
            continue;
        }

        // --icmp-type <type>
        if (arg == "--icmp-type") {
            if (i + 1 >= rule_args.size()) { err = "--icmp-type requires an argument"; return rule; }
            std::string type_str = rule_args[++i];
            if (type_str == "!") { negated = !negated; if (i + 1 >= rule_args.size()) { err = "--icmp-type requires an argument"; return rule; } type_str = rule_args[++i]; }
            try {
                uint8_t icmp_type = static_cast<uint8_t>(std::stoi(type_str));
                rule.matches.push_back(std::make_unique<IcmpTypeMatch>(icmp_type, negated));
            } catch (...) { err = "Invalid icmp-type: " + type_str; return rule; }
            continue;
        }

        // --sports / --dports (multiport extension)
        if (arg == "--sports" || arg == "--dports") {
            if (i + 1 >= rule_args.size()) { err = arg + " requires an argument"; return rule; }
            std::string ports = rule_args[++i];
            if (ports == "!") { negated = !negated; if (i + 1 >= rule_args.size()) { err = arg + " requires an argument"; return rule; } ports = rule_args[++i]; }
            bool is_src = (arg == "--sports");
            try {
                rule.matches.push_back(MultiportMatch::Parse(ports, is_src, negated));
            } catch (const std::exception& e) { err = e.what(); return rule; }
            continue;
        }

        // --state (state extension)
        if (arg == "--state") {
            if (i + 1 >= rule_args.size()) { err = "--state requires an argument"; return rule; }
            std::string states = rule_args[++i];
            if (states == "!") { negated = !negated; if (i + 1 >= rule_args.size()) { err = "--state requires an argument"; return rule; } states = rule_args[++i]; }
            try {
                rule.matches.push_back(StateMatch::Parse(states, negated));
            } catch (const std::exception& e) { err = e.what(); return rule; }
            continue;
        }
    }

    if (!has_target) {
        err = "Rule is missing -j target";
        return rule;
    }

    rule.target = std::move(target);
    return rule;
}

}  // namespace winiptables
