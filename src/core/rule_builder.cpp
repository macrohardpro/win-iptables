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

    for (size_t i = 0; i < rule_args.size(); ++i) {
        const std::string& arg = rule_args[i];

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
            if (i + 1 < rule_args.size()) ++i;  // consume but ignore for now
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

        // -p protocol
        if (arg == "-p" || arg == "--protocol") {
            if (i + 1 >= rule_args.size()) { err = "-p requires an argument"; return rule; }
            bool negated = false;
            std::string proto = rule_args[++i];
            if (proto == "!") {
                negated = true;
                if (i + 1 < rule_args.size()) proto = rule_args[++i];
            }
            rule.matches.push_back(
                std::make_unique<ProtocolMatch>(ParseProtocol(proto), negated));
            continue;
        }

        // -s source IP/CIDR
        if (arg == "-s" || arg == "--source") {
            if (i + 1 >= rule_args.size()) { err = "-s requires an argument"; return rule; }
            std::string cidr = rule_args[++i];
            bool negated = false;
            if (cidr == "!") {
                negated = true;
                if (i + 1 < rule_args.size()) cidr = rule_args[++i];
            }
            try {
                auto r = ParseCidr(cidr);
                rule.matches.push_back(
                    std::make_unique<SrcIpMatch>(r.network_be, r.prefix_len, negated));
            } catch (...) { err = "Invalid source IP: " + cidr; return rule; }
            continue;
        }

        // -d destination IP/CIDR
        if (arg == "-d" || arg == "--destination") {
            if (i + 1 >= rule_args.size()) { err = "-d requires an argument"; return rule; }
            std::string cidr = rule_args[++i];
            bool negated = false;
            if (cidr == "!") {
                negated = true;
                if (i + 1 < rule_args.size()) cidr = rule_args[++i];
            }
            try {
                auto r = ParseCidr(cidr);
                rule.matches.push_back(
                    std::make_unique<DstIpMatch>(r.network_be, r.prefix_len, negated));
            } catch (...) { err = "Invalid destination IP: " + cidr; return rule; }
            continue;
        }

        // -i in-interface
        if (arg == "-i" || arg == "--in-interface") {
            if (i + 1 >= rule_args.size()) { err = "-i requires an argument"; return rule; }
            bool negated = false;
            std::string iface = rule_args[++i];
            if (iface == "!") {
                negated = true;
                if (i + 1 < rule_args.size()) iface = rule_args[++i];
            }
            rule.matches.push_back(std::make_unique<InIfaceMatch>(0, negated));
            continue;
        }

        // -o out-interface
        if (arg == "-o" || arg == "--out-interface") {
            if (i + 1 >= rule_args.size()) { err = "-o requires an argument"; return rule; }
            bool negated = false;
            std::string iface = rule_args[++i];
            if (iface == "!") {
                negated = true;
                if (i + 1 < rule_args.size()) iface = rule_args[++i];
            }
            rule.matches.push_back(std::make_unique<OutIfaceMatch>(0, negated));
            continue;
        }

        // --dport destination port
        if (arg == "--dport" || arg == "--destination-port") {
            if (i + 1 >= rule_args.size()) { err = "--dport requires an argument"; return rule; }
            std::string port = rule_args[++i];
            bool negated = false;
            if (port == "!") {
                negated = true;
                if (i + 1 < rule_args.size()) port = rule_args[++i];
            }
            auto [lo, hi] = ParsePortRange(port);
            rule.matches.push_back(std::make_unique<DstPortMatch>(lo, hi, negated));
            continue;
        }

        // --sport source port
        if (arg == "--sport" || arg == "--source-port") {
            if (i + 1 >= rule_args.size()) { err = "--sport requires an argument"; return rule; }
            std::string port = rule_args[++i];
            bool negated = false;
            if (port == "!") {
                negated = true;
                if (i + 1 < rule_args.size()) port = rule_args[++i];
            }
            auto [lo, hi] = ParsePortRange(port);
            rule.matches.push_back(std::make_unique<SrcPortMatch>(lo, hi, negated));
            continue;
        }

        // -m match extension (module name consumed; options handled by specific args above)
        if (arg == "-m" || arg == "--match") {
            if (i + 1 < rule_args.size()) ++i;
            continue;
        }

        // Standalone negation prefix
        if (arg == "!") {
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
