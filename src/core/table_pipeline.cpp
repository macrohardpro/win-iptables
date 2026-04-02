// table_pipeline.cpp -- TablePipeline implementation (Task 8.2 / 8.3)
#include "winiptables/table_pipeline.hpp"

namespace winiptables {

// ---------------------------------------------------------------------------
// Task 8.3: eval_table() -- Evaluate chains in specified table by (TableKind, chain_name)
//
// Get chain directly from RuleStore, evaluate rules one by one, process ACCEPT/DROP/RETURN/JUMP targets.
// If chain does not exist, return Accept (skip this step).
// ---------------------------------------------------------------------------
Verdict TablePipeline::eval_table(TableKind table, const std::string& chain_name,
                                   const Packet& packet,
                                   PipelineContext& ctx) const {
    const Chain* chain = rule_store_.get_chain(table, chain_name);
    if (!chain) return Verdict::Accept;  // Chain does not exist, skip

    // Pass Chain* directly to avoid cross-table name ambiguity
    // (e.g. mangle/PREROUTING vs nat/PREROUTING both named "PREROUTING")
    return engine_.evaluate(chain, packet, ctx.eval_ctx);
}

// ---------------------------------------------------------------------------
// Task 8.2: process() -- Process packets according to iptables standard flow
//
// INBOUND:
//   raw/PREROUTING -> mangle/PREROUTING -> nat/PREROUTING -> mangle/INPUT -> filter/INPUT
//
// OUTBOUND:
//   raw/OUTPUT -> mangle/OUTPUT -> nat/OUTPUT -> filter/OUTPUT
//             -> mangle/POSTROUTING -> nat/POSTROUTING
//
// FORWARD:
//   raw/PREROUTING -> mangle/PREROUTING -> mangle/FORWARD -> filter/FORWARD
//                  -> mangle/POSTROUTING
// ---------------------------------------------------------------------------
Verdict TablePipeline::process(Packet& packet, PipelineContext& ctx) const {
    // Helper macro: evaluate a chain, return immediately if Drop
#define EVAL(tbl, chain)                                                    \
    do {                                                                    \
        Verdict _v = eval_table(TableKind::tbl, (chain), packet, ctx);     \
        if (_v == Verdict::Drop) return Verdict::Drop;                      \
    } while (0)

    switch (ctx.direction) {
        case Direction::kInbound:
            EVAL(kRaw,    "PREROUTING");  // raw/PREROUTING (reserved, currently empty)
            EVAL(kMangle, "PREROUTING");  // mangle/PREROUTING
            EVAL(kNat,    "PREROUTING");  // nat/PREROUTING
            EVAL(kMangle, "INPUT");       // mangle/INPUT
            EVAL(kFilter, "INPUT");       // filter/INPUT
            break;

        case Direction::kOutbound:
            EVAL(kRaw,    "OUTPUT");      // raw/OUTPUT (reserved, currently empty)
            EVAL(kMangle, "OUTPUT");      // mangle/OUTPUT
            EVAL(kNat,    "OUTPUT");      // nat/OUTPUT
            EVAL(kFilter, "OUTPUT");      // filter/OUTPUT
            EVAL(kMangle, "POSTROUTING"); // mangle/POSTROUTING
            EVAL(kNat,    "POSTROUTING"); // nat/POSTROUTING
            break;

        case Direction::kForward:
            EVAL(kRaw,    "PREROUTING");  // raw/PREROUTING (reserved, currently empty)
            EVAL(kMangle, "PREROUTING");  // mangle/PREROUTING
            EVAL(kMangle, "FORWARD");     // mangle/FORWARD
            EVAL(kFilter, "FORWARD");     // filter/FORWARD
            EVAL(kMangle, "POSTROUTING"); // mangle/POSTROUTING
            break;
    }

#undef EVAL
    return Verdict::Accept;
}

}  // namespace winiptables