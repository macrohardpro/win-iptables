// rule_engine.cpp -- RuleEngine implementation (Task 7.2-7.5)
#include "winiptables/rule_engine.hpp"
#include "winiptables/imatch.hpp"
#include "winiptables/log.hpp"
#include "winiptables/packet.hpp"

// Windows event log API
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <string>

namespace winiptables {

// ---------------------------------------------------------------------------
// Helper: format packet five-tuple for log messages
// ---------------------------------------------------------------------------

static std::string FormatPacket(const Packet& pkt) {
    const char* proto = (pkt.protocol == 6)  ? "tcp"
                      : (pkt.protocol == 17) ? "udp"
                      : (pkt.protocol == 1)  ? "icmp"
                      : "proto";
    std::string s = pkt.SrcIpStr();
    if (pkt.src_port) s += ':' + std::to_string(pkt.src_port);
    s += " -> ";
    s += pkt.DstIpStr();
    if (pkt.dst_port) s += ':' + std::to_string(pkt.dst_port);
    s += " (";
    s += proto;
    s += ')';
    return s;
}

// ---------------------------------------------------------------------------
// Task 7.2: evaluate() -- Evaluate in chain rule order, support ACCEPT/DROP/RETURN/JUMP
// ---------------------------------------------------------------------------

Verdict RuleEngine::evaluate(const std::string& chain_name,
                              const Packet& packet,
                              EvalContext& ctx) const {
    const Chain* chain = rule_store_.get_chain_any_table(chain_name);
    return evaluate(chain, packet, ctx);
}

Verdict RuleEngine::evaluate(const Chain* chain,
                              const Packet& packet,
                              EvalContext& ctx) const {
    if (!chain) return Verdict::Drop;

    for (const auto& rule_ptr : chain->rules) {
        const Rule& rule = *rule_ptr;

        // Task 7.4: Check all match conditions
        if (!matches_all(rule, packet, ctx))
            continue;

        // Task 7.5: Atomically increment rule counter
        rule.counters.Increment(packet.size());

        switch (rule.target.kind) {
            case Target::Kind::kAccept:
                LOG_DEBUG("ACCEPT chain={} {}", chain->name, FormatPacket(packet));
                return Verdict::Accept;

            case Target::Kind::kDrop:
                LOG_INFO("DROP chain={} {}", chain->name, FormatPacket(packet));
                return Verdict::Drop;

            case Target::Kind::kReturn:
                return Verdict::Return;

            case Target::Kind::kJump: {
                LOG_DEBUG("JUMP chain={} -> {} {}", chain->name,
                          rule.target.jump_chain, FormatPacket(packet));
                Verdict v = evaluate(rule.target.jump_chain, packet, ctx);
                if (v == Verdict::Return)
                    continue;  // RETURN from subchain, continue current chain
                return v;
            }

            // NAT targets: apply side effect then ACCEPT (terminating, like real iptables)
            case Target::Kind::kDnat:
                LOG_INFO("DNAT chain={} {} -> {}", chain->name,
                         FormatPacket(packet), rule.target.to_addr);
                execute_action(rule.target, packet, ctx);
                return Verdict::Accept;

            case Target::Kind::kSnat:
                LOG_INFO("SNAT chain={} {} -> {}", chain->name,
                         FormatPacket(packet), rule.target.to_addr);
                execute_action(rule.target, packet, ctx);
                return Verdict::Accept;

            case Target::Kind::kMasquerade:
                LOG_INFO("MASQUERADE chain={} {}", chain->name, FormatPacket(packet));
                execute_action(rule.target, packet, ctx);
                return Verdict::Accept;

            // Non-terminating targets: apply side effect and continue to next rule
            case Target::Kind::kLog:
            case Target::Kind::kReject:
                execute_action(rule.target, packet, ctx);
                if (rule.target.kind == Target::Kind::kReject) {
                    LOG_INFO("REJECT chain={} {}", chain->name, FormatPacket(packet));
                    return Verdict::Drop;  // REJECT terminates and drops
                }
                break;

            default:
                execute_action(rule.target, packet, ctx);
                break;
        }
    }

    // No rule matched: use chain default policy
    if (chain->policy.has_value())
        return verdict_from_target(*chain->policy);

    // User-defined chain has no policy: return Return (return to calling chain)
    return Verdict::Return;
}

// ---------------------------------------------------------------------------
// Task 7.4: matches_all() -- Iterate all IMatch conditions, return true only if all match
// ---------------------------------------------------------------------------

bool RuleEngine::matches_all(const Rule& rule, const Packet& pkt,
                              EvalContext& /*ctx*/) const {
    MatchContext match_ctx{};
    for (const auto& match : rule.matches) {
        if (!match->Matches(pkt, match_ctx))
            return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Task 7.3: execute_action() -- Handle non-terminating target actions
// ---------------------------------------------------------------------------

void RuleEngine::execute_action(const Target& target, const Packet& pkt,
                                 EvalContext& ctx) const {
    switch (target.kind) {

        // LOG: Write Windows event log, also write to ctx.log_buffer (convenient for testing)
        case Target::Kind::kLog: {
            // Construct log message
            std::string msg = target.log_prefix;
            if (!msg.empty() && msg.back() != ' ')
                msg += ' ';
            msg += "SRC=";
            // Simple source IP formatting (IPv4)
            if (pkt.af == AddressFamily::kIPv4) {
                const auto& s = pkt.src_ip.v4;
                msg += std::to_string(s[0]) + '.' + std::to_string(s[1]) + '.'
                     + std::to_string(s[2]) + '.' + std::to_string(s[3]);
                msg += " DST=";
                const auto& d = pkt.dst_ip.v4;
                msg += std::to_string(d[0]) + '.' + std::to_string(d[1]) + '.'
                     + std::to_string(d[2]) + '.' + std::to_string(d[3]);
            }
            msg += " PROTO=" + std::to_string(pkt.protocol);

            // Write to context buffer (can be checked in tests)
            if (!ctx.log_buffer.empty())
                ctx.log_buffer += '\n';
            ctx.log_buffer += msg;

            // Try to write Windows event log; fall back to OutputDebugString on failure
            HANDLE hEventLog = RegisterEventSourceW(nullptr, L"winiptables");
            if (hEventLog) {
                // Convert to wide characters
                int wlen = MultiByteToWideChar(CP_UTF8, 0, msg.c_str(),
                                               static_cast<int>(msg.size()),
                                               nullptr, 0);
                std::wstring wmsg(wlen, L'\0');
                MultiByteToWideChar(CP_UTF8, 0, msg.c_str(),
                                    static_cast<int>(msg.size()),
                                    wmsg.data(), wlen);
                const wchar_t* strings[] = {wmsg.c_str()};
                ReportEventW(hEventLog,
                             EVENTLOG_INFORMATION_TYPE,
                             0,
                             0,
                             nullptr,
                             1,
                             0,
                             strings,
                             nullptr);
                DeregisterEventSource(hEventLog);
            } else {
                OutputDebugStringA(msg.c_str());
            }
            break;
        }

        // REJECT: Mark packet needs to send ICMP unreachable response
        case Target::Kind::kReject: {
            ctx.rejected = true;
            ctx.reject_icmp_type = target.reject_with;
            break;
        }

        // MASQUERADE: Source address masquerade (SNAT to egress IP, mark as needing masquerade here)
        case Target::Kind::kMasquerade: {
            // Mark as MASQUERADE, actual egress IP is filled by PacketCapture layer
            ctx.nat_src_addr = "MASQUERADE";
            break;
        }

        // DNAT: Modify destination address
        case Target::Kind::kDnat: {
            ctx.nat_dst_addr = target.to_addr;
            break;
        }

        // SNAT: Modify source address
        case Target::Kind::kSnat: {
            ctx.nat_src_addr = target.to_addr;
            break;
        }

        default:
            break;
    }
}

// ---------------------------------------------------------------------------
// Helper: Convert Target to Verdict (used for chain default policies)
// ---------------------------------------------------------------------------

Verdict RuleEngine::verdict_from_target(const Target& t) {
    switch (t.kind) {
        case Target::Kind::kAccept: return Verdict::Accept;
        case Target::Kind::kDrop:   return Verdict::Drop;
        default:                    return Verdict::Drop;
    }
}

}  // namespace winiptables