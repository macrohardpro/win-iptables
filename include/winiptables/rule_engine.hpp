#pragma once
// rule_engine.hpp -- RuleEngine declarations (Task 7.1)

#include "winiptables/model.hpp"
#include "winiptables/packet.hpp"
#include "winiptables/rule_store.hpp"

#include <string>

namespace winiptables {

// Rule evaluation context: passes side-effect information during a single packet evaluation
struct EvalContext {
    // REJECT target: mark packet needs to send ICMP unreachable response
    bool rejected = false;
    IcmpType reject_icmp_type{};  // ICMP type/code

    // NAT target: modified source/destination address (format "ip" or "ip:port")
    std::string nat_src_addr;  // SNAT / MASQUERADE modified source address
    std::string nat_dst_addr;  // DNAT modified destination address

    // LOG target: log output buffer (can be checked in tests)
    std::string log_buffer;
};

// Rule evaluation verdict
enum class Verdict {
    Accept,
    Drop,
    Return,
};

// RuleEngine: performs rule matching and target actions on packets
class RuleEngine {
public:
    explicit RuleEngine(const RuleStore& rule_store)
        : rule_store_(rule_store) {}

    // Evaluate packet in specified chain, return final verdict
    // chain_name: chain name (e.g., "INPUT", "FORWARD")
    // packet: packet to evaluate
    // ctx: evaluation context, used to pass NAT/LOG/REJECT side effects
    Verdict evaluate(const std::string& chain_name,
                     const Packet& packet,
                     EvalContext& ctx) const;

    // Evaluate packet against a specific Chain pointer (table-aware, avoids cross-table ambiguity)
    Verdict evaluate(const Chain* chain,
                     const Packet& packet,
                     EvalContext& ctx) const;

private:
    const RuleStore& rule_store_;

    // Check all IMatch conditions for a rule, return true only if all match (Task 7.4)
    bool matches_all(const Rule& rule, const Packet& pkt,
                     EvalContext& ctx) const;

    // Execute non-terminating target actions (LOG/REJECT/MASQUERADE/DNAT/SNAT) (Task 7.3)
    void execute_action(const Target& target, const Packet& pkt,
                        EvalContext& ctx) const;

    // Convert Target to Verdict (only used for chain default policies)
    static Verdict verdict_from_target(const Target& t);
};

}  // namespace winiptables