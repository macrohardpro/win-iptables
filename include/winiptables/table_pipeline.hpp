#pragma once
// table_pipeline.hpp — TablePipeline declaration
// Orchestrates table processing in raw(reserved)->mangle->nat->filter order

#include "winiptables/model.hpp"
#include "winiptables/packet.hpp"
#include "winiptables/rule_engine.hpp"
#include "winiptables/rule_store.hpp"

#include <string>

namespace winiptables {

// Packet processing pipeline context.
// Holds packet direction, rule evaluation context, and a reference to RuleEngine.
struct PipelineContext {
    Direction   direction;  // packet direction: kInbound / kOutbound / kForward
    EvalContext eval_ctx;   // rule evaluation context (NAT/LOG/REJECT side effects)
};

// TablePipeline: orchestrates table/chain processing in standard iptables order.
//
// INBOUND:
//   raw/PREROUTING -> mangle/PREROUTING -> nat/PREROUTING -> mangle/INPUT -> filter/INPUT
//
// OUTBOUND:
//   raw/OUTPUT -> mangle/OUTPUT -> nat/OUTPUT -> filter/OUTPUT -> mangle/POSTROUTING -> nat/POSTROUTING
//
// FORWARD:
//   raw/PREROUTING -> mangle/PREROUTING -> mangle/FORWARD -> filter/FORWARD -> mangle/POSTROUTING
class TablePipeline {
public:
    // Holds a reference to RuleStore (caller is responsible for lifetime).
    explicit TablePipeline(const RuleStore& rule_store)
        : rule_store_(rule_store), engine_(rule_store) {}

    // Process a packet through the pipeline and return the final verdict.
    Verdict process(Packet& packet, PipelineContext& ctx) const;

private:
    const RuleStore& rule_store_;
    RuleEngine       engine_;  // reuse a single engine instance

    // Evaluate the named chain in the given table.
    // Returns Verdict::Accept if the chain does not exist (skip).
    Verdict eval_table(TableKind table, const std::string& chain_name,
                       const Packet& packet, PipelineContext& ctx) const;
};

}  // namespace winiptables
