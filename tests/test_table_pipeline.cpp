// test_table_pipeline.cpp -- TablePipeline unit tests (Task 8.4)
#include <gtest/gtest.h>
#include "winiptables/table_pipeline.hpp"
#include "winiptables/rule_store.hpp"
#include "winiptables/model.hpp"
#include "winiptables/packet.hpp"
#include "winiptables/imatch.hpp"
#include <memory>
#include <string>

namespace winiptables {

// ---------------------------------------------------------------------------
// Helper utilities
// ---------------------------------------------------------------------------

static Packet make_tcp_packet() {
    Packet p;
    p.af = AddressFamily::kIPv4;
    p.src_ip.af = AddressFamily::kIPv4;
    p.src_ip.v4[0]=192; p.src_ip.v4[1]=168; p.src_ip.v4[2]=1; p.src_ip.v4[3]=1;
    p.dst_ip.af = AddressFamily::kIPv4;
    p.dst_ip.v4[0]=10; p.dst_ip.v4[1]=0; p.dst_ip.v4[2]=0; p.dst_ip.v4[3]=1;
    p.protocol = 6;  // TCP
    p.src_port = 12345;
    p.dst_port = 80;
    p.raw_data.resize(60, 0);
    return p;
}

static PipelineContext make_ctx(Direction dir) {
    PipelineContext ctx;
    ctx.direction = dir;
    return ctx;
}

class AlwaysMatch : public IMatch {
public:
    bool Matches(const Packet&, const MatchContext&) const override { return true; }
    std::string ToRuleText() const override { return "-m always"; }
};

class NeverMatch : public IMatch {
public:
    bool Matches(const Packet&, const MatchContext&) const override { return false; }
    std::string ToRuleText() const override { return "-m never"; }
};

// ---------------------------------------------------------------------------
// Test 1: All directions return Accept when no rules exist (default policy ACCEPT)
// ---------------------------------------------------------------------------

TEST(TablePipelineTest, EmptyStoreInboundAccepts) {
    RuleStore store;
    TablePipeline pipeline(store);
    Packet pkt = make_tcp_packet();
    PipelineContext ctx = make_ctx(Direction::kInbound);
    EXPECT_EQ(pipeline.process(pkt, ctx), Verdict::Accept);
}

TEST(TablePipelineTest, EmptyStoreOutboundAccepts) {
    RuleStore store;
    TablePipeline pipeline(store);
    Packet pkt = make_tcp_packet();
    PipelineContext ctx = make_ctx(Direction::kOutbound);
    EXPECT_EQ(pipeline.process(pkt, ctx), Verdict::Accept);
}

TEST(TablePipelineTest, EmptyStoreForwardAccepts) {
    RuleStore store;
    TablePipeline pipeline(store);
    Packet pkt = make_tcp_packet();
    PipelineContext ctx = make_ctx(Direction::kForward);
    EXPECT_EQ(pipeline.process(pkt, ctx), Verdict::Accept);
}

// ---------------------------------------------------------------------------
// Test 2: INBOUND -- DROP rule in filter/INPUT takes effect
// ---------------------------------------------------------------------------

TEST(TablePipelineTest, InboundFilterInputDropReturnsDropp) {
    RuleStore store;
    Rule r; r.target.kind = Target::Kind::kDrop;
    r.matches.push_back(std::make_unique<AlwaysMatch>());
    store.append_rule(TableKind::kFilter, "INPUT", std::move(r));

    TablePipeline pipeline(store);
    Packet pkt = make_tcp_packet();
    PipelineContext ctx = make_ctx(Direction::kInbound);
    EXPECT_EQ(pipeline.process(pkt, ctx), Verdict::Drop);
}

TEST(TablePipelineTest, InboundFilterInputAcceptReturnsAccept) {
    RuleStore store;
    Rule r; r.target.kind = Target::Kind::kAccept;
    r.matches.push_back(std::make_unique<AlwaysMatch>());
    store.append_rule(TableKind::kFilter, "INPUT", std::move(r));

    TablePipeline pipeline(store);
    Packet pkt = make_tcp_packet();
    PipelineContext ctx = make_ctx(Direction::kInbound);
    EXPECT_EQ(pipeline.process(pkt, ctx), Verdict::Accept);
}

// ---------------------------------------------------------------------------
// Test 3: OUTBOUND -- DROP rule in filter/OUTPUT takes effect
// ---------------------------------------------------------------------------

TEST(TablePipelineTest, OutboundFilterOutputDropReturnsDrop) {
    RuleStore store;
    Rule r; r.target.kind = Target::Kind::kDrop;
    r.matches.push_back(std::make_unique<AlwaysMatch>());
    store.append_rule(TableKind::kFilter, "OUTPUT", std::move(r));

    TablePipeline pipeline(store);
    Packet pkt = make_tcp_packet();
    PipelineContext ctx = make_ctx(Direction::kOutbound);
    EXPECT_EQ(pipeline.process(pkt, ctx), Verdict::Drop);
}

// ---------------------------------------------------------------------------
// Test 4: FORWARD -- DROP rule in filter/FORWARD takes effect
// ---------------------------------------------------------------------------

TEST(TablePipelineTest, ForwardFilterForwardDropReturnsDrop) {
    RuleStore store;
    Rule r; r.target.kind = Target::Kind::kDrop;
    r.matches.push_back(std::make_unique<AlwaysMatch>());
    store.append_rule(TableKind::kFilter, "FORWARD", std::move(r));

    TablePipeline pipeline(store);
    Packet pkt = make_tcp_packet();
    PipelineContext ctx = make_ctx(Direction::kForward);
    EXPECT_EQ(pipeline.process(pkt, ctx), Verdict::Drop);
}

// ---------------------------------------------------------------------------
// Test 5: DROP in mangle table blocks subsequent nat and filter table processing
// ---------------------------------------------------------------------------

TEST(TablePipelineTest, InboundMangleDropStopsNatAndFilter) {
    RuleStore store;

    // mangle/PREROUTING DROP
    {
        Rule r; r.target.kind = Target::Kind::kDrop;
        r.matches.push_back(std::make_unique<AlwaysMatch>());
        store.append_rule(TableKind::kMangle, "PREROUTING", std::move(r));
    }
    // filter/INPUT ACCEPT (should not be executed)
    {
        Rule r; r.target.kind = Target::Kind::kAccept;
        r.matches.push_back(std::make_unique<AlwaysMatch>());
        store.append_rule(TableKind::kFilter, "INPUT", std::move(r));
    }

    TablePipeline pipeline(store);
    Packet pkt = make_tcp_packet();
    PipelineContext ctx = make_ctx(Direction::kInbound);
    EXPECT_EQ(pipeline.process(pkt, ctx), Verdict::Drop);
}

TEST(TablePipelineTest, OutboundMangleDropStopsNatAndFilter) {
    RuleStore store;

    // mangle/OUTPUT DROP
    {
        Rule r; r.target.kind = Target::Kind::kDrop;
        r.matches.push_back(std::make_unique<AlwaysMatch>());
        store.append_rule(TableKind::kMangle, "OUTPUT", std::move(r));
    }
    // filter/OUTPUT ACCEPT (should not be executed)
    {
        Rule r; r.target.kind = Target::Kind::kAccept;
        r.matches.push_back(std::make_unique<AlwaysMatch>());
        store.append_rule(TableKind::kFilter, "OUTPUT", std::move(r));
    }

    TablePipeline pipeline(store);
    Packet pkt = make_tcp_packet();
    PipelineContext ctx = make_ctx(Direction::kOutbound);
    EXPECT_EQ(pipeline.process(pkt, ctx), Verdict::Drop);
}

// ---------------------------------------------------------------------------
// Test 6: DROP in nat table blocks subsequent filter table processing
// ---------------------------------------------------------------------------

TEST(TablePipelineTest, InboundNatDropStopsFilter) {
    RuleStore store;

    // nat/PREROUTING DROP
    {
        Rule r; r.target.kind = Target::Kind::kDrop;
        r.matches.push_back(std::make_unique<AlwaysMatch>());
        store.append_rule(TableKind::kNat, "PREROUTING", std::move(r));
    }
    // filter/INPUT ACCEPT (should not be executed)
    {
        Rule r; r.target.kind = Target::Kind::kAccept;
        r.matches.push_back(std::make_unique<AlwaysMatch>());
        store.append_rule(TableKind::kFilter, "INPUT", std::move(r));
    }

    TablePipeline pipeline(store);
    Packet pkt = make_tcp_packet();
    PipelineContext ctx = make_ctx(Direction::kInbound);
    EXPECT_EQ(pipeline.process(pkt, ctx), Verdict::Drop);
}

// ---------------------------------------------------------------------------
// Test 7: INBOUND uses INPUT chain, OUTBOUND uses OUTPUT chain, FORWARD uses FORWARD chain
// Verifies direction routing correctness: DROP in wrong chain does not affect other directions
// ---------------------------------------------------------------------------

TEST(TablePipelineTest, InboundUsesInputChainNotOutput) {
    RuleStore store;
    // filter/OUTPUT DROP (should not affect INBOUND)
    {
        Rule r; r.target.kind = Target::Kind::kDrop;
        r.matches.push_back(std::make_unique<AlwaysMatch>());
        store.append_rule(TableKind::kFilter, "OUTPUT", std::move(r));
    }

    TablePipeline pipeline(store);
    Packet pkt = make_tcp_packet();
    PipelineContext ctx = make_ctx(Direction::kInbound);
    EXPECT_EQ(pipeline.process(pkt, ctx), Verdict::Accept);
}

TEST(TablePipelineTest, OutboundUsesOutputChainNotInput) {
    RuleStore store;
    // filter/INPUT DROP (should not affect OUTBOUND)
    {
        Rule r; r.target.kind = Target::Kind::kDrop;
        r.matches.push_back(std::make_unique<AlwaysMatch>());
        store.append_rule(TableKind::kFilter, "INPUT", std::move(r));
    }

    TablePipeline pipeline(store);
    Packet pkt = make_tcp_packet();
    PipelineContext ctx = make_ctx(Direction::kOutbound);
    EXPECT_EQ(pipeline.process(pkt, ctx), Verdict::Accept);
}

TEST(TablePipelineTest, ForwardUsesForwardChainNotInput) {
    RuleStore store;
    // filter/INPUT DROP (should not affect FORWARD)
    {
        Rule r; r.target.kind = Target::Kind::kDrop;
        r.matches.push_back(std::make_unique<AlwaysMatch>());
        store.append_rule(TableKind::kFilter, "INPUT", std::move(r));
    }

    TablePipeline pipeline(store);
    Packet pkt = make_tcp_packet();
    PipelineContext ctx = make_ctx(Direction::kForward);
    EXPECT_EQ(pipeline.process(pkt, ctx), Verdict::Accept);
}

// ---------------------------------------------------------------------------
// Test 8: Default policy behavior -- when chain default policy is DROP, no matching rules returns Drop
// ---------------------------------------------------------------------------

TEST(TablePipelineTest, InboundFilterInputDefaultDropPolicyApplied) {
    RuleStore store;
    store.set_policy(TableKind::kFilter, "INPUT", Target{Target::Kind::kDrop});

    TablePipeline pipeline(store);
    Packet pkt = make_tcp_packet();
    PipelineContext ctx = make_ctx(Direction::kInbound);
    EXPECT_EQ(pipeline.process(pkt, ctx), Verdict::Drop);
}

TEST(TablePipelineTest, OutboundFilterOutputDefaultDropPolicyApplied) {
    RuleStore store;
    store.set_policy(TableKind::kFilter, "OUTPUT", Target{Target::Kind::kDrop});

    TablePipeline pipeline(store);
    Packet pkt = make_tcp_packet();
    PipelineContext ctx = make_ctx(Direction::kOutbound);
    EXPECT_EQ(pipeline.process(pkt, ctx), Verdict::Drop);
}

TEST(TablePipelineTest, ForwardFilterForwardDefaultDropPolicyApplied) {
    RuleStore store;
    store.set_policy(TableKind::kFilter, "FORWARD", Target{Target::Kind::kDrop});

    TablePipeline pipeline(store);
    Packet pkt = make_tcp_packet();
    PipelineContext ctx = make_ctx(Direction::kForward);
    EXPECT_EQ(pipeline.process(pkt, ctx), Verdict::Drop);
}

// ---------------------------------------------------------------------------
// Test 9: After mangle table rules pass, filter table rules still execute
// ---------------------------------------------------------------------------

TEST(TablePipelineTest, InboundMangleAcceptThenFilterDropReturnsDrop) {
    RuleStore store;

    // mangle/INPUT ACCEPT
    {
        Rule r; r.target.kind = Target::Kind::kAccept;
        r.matches.push_back(std::make_unique<AlwaysMatch>());
        store.append_rule(TableKind::kMangle, "INPUT", std::move(r));
    }
    // filter/INPUT DROP
    {
        Rule r; r.target.kind = Target::Kind::kDrop;
        r.matches.push_back(std::make_unique<AlwaysMatch>());
        store.append_rule(TableKind::kFilter, "INPUT", std::move(r));
    }

    TablePipeline pipeline(store);
    Packet pkt = make_tcp_packet();
    PipelineContext ctx = make_ctx(Direction::kInbound);
    EXPECT_EQ(pipeline.process(pkt, ctx), Verdict::Drop);
}

// ---------------------------------------------------------------------------
// Test 10: OUTBOUND flow includes POSTROUTING chain
// mangle/POSTROUTING DROP should take effect after filter/OUTPUT ACCEPT
// ---------------------------------------------------------------------------

TEST(TablePipelineTest, OutboundManglePostroutingDropAfterFilterAccept) {
    RuleStore store;

    // filter/OUTPUT ACCEPT
    {
        Rule r; r.target.kind = Target::Kind::kAccept;
        r.matches.push_back(std::make_unique<AlwaysMatch>());
        store.append_rule(TableKind::kFilter, "OUTPUT", std::move(r));
    }
    // mangle/POSTROUTING DROP
    {
        Rule r; r.target.kind = Target::Kind::kDrop;
        r.matches.push_back(std::make_unique<AlwaysMatch>());
        store.append_rule(TableKind::kMangle, "POSTROUTING", std::move(r));
    }

    TablePipeline pipeline(store);
    Packet pkt = make_tcp_packet();
    PipelineContext ctx = make_ctx(Direction::kOutbound);
    EXPECT_EQ(pipeline.process(pkt, ctx), Verdict::Drop);
}

// ---------------------------------------------------------------------------
// Test 11: FORWARD flow includes mangle/POSTROUTING, does not include filter/INPUT or filter/OUTPUT
// ---------------------------------------------------------------------------

TEST(TablePipelineTest, ForwardManglePostroutingDropReturnsDrop) {
    RuleStore store;

    // mangle/POSTROUTING DROP
    {
        Rule r; r.target.kind = Target::Kind::kDrop;
        r.matches.push_back(std::make_unique<AlwaysMatch>());
        store.append_rule(TableKind::kMangle, "POSTROUTING", std::move(r));
    }

    TablePipeline pipeline(store);
    Packet pkt = make_tcp_packet();
    PipelineContext ctx = make_ctx(Direction::kForward);
    EXPECT_EQ(pipeline.process(pkt, ctx), Verdict::Drop);
}

TEST(TablePipelineTest, ForwardDoesNotUseInputOrOutputChains) {
    RuleStore store;

    // filter/INPUT DROP and filter/OUTPUT DROP should not affect FORWARD
    {
        Rule r; r.target.kind = Target::Kind::kDrop;
        r.matches.push_back(std::make_unique<AlwaysMatch>());
        store.append_rule(TableKind::kFilter, "INPUT", std::move(r));
    }
    {
        Rule r; r.target.kind = Target::Kind::kDrop;
        r.matches.push_back(std::make_unique<AlwaysMatch>());
        store.append_rule(TableKind::kFilter, "OUTPUT", std::move(r));
    }

    TablePipeline pipeline(store);
    Packet pkt = make_tcp_packet();
    PipelineContext ctx = make_ctx(Direction::kForward);
    EXPECT_EQ(pipeline.process(pkt, ctx), Verdict::Accept);
}

// ---------------------------------------------------------------------------
// Test 12: eval_table returns Accept (skip) for non-existent chains
// Verified in raw table (currently no rules): non-existent raw table chains do not affect result
// ---------------------------------------------------------------------------

TEST(TablePipelineTest, MissingChainIsSkippedAndReturnsAccept) {
    RuleStore store;
    // Only put ACCEPT in filter/INPUT, other chains are empty
    {
        Rule r; r.target.kind = Target::Kind::kAccept;
        r.matches.push_back(std::make_unique<AlwaysMatch>());
        store.append_rule(TableKind::kFilter, "INPUT", std::move(r));
    }

    TablePipeline pipeline(store);
    Packet pkt = make_tcp_packet();
    PipelineContext ctx = make_ctx(Direction::kInbound);
    // mangle/PREROUTING, nat/PREROUTING, mangle/INPUT do not exist, should be skipped
    EXPECT_EQ(pipeline.process(pkt, ctx), Verdict::Accept);
}

// ---------------------------------------------------------------------------
// Test 13: Non-matching rules do not affect result (NeverMatch rules are skipped)
// ---------------------------------------------------------------------------

TEST(TablePipelineTest, NonMatchingRuleInFilterIsSkipped) {
    RuleStore store;

    // filter/INPUT: NeverMatch DROP (does not match, skipped)
    {
        Rule r; r.target.kind = Target::Kind::kDrop;
        r.matches.push_back(std::make_unique<NeverMatch>());
        store.append_rule(TableKind::kFilter, "INPUT", std::move(r));
    }

    TablePipeline pipeline(store);
    Packet pkt = make_tcp_packet();
    PipelineContext ctx = make_ctx(Direction::kInbound);
    EXPECT_EQ(pipeline.process(pkt, ctx), Verdict::Accept);
}

// ---------------------------------------------------------------------------
// Test 14: Parameterized test -- correct chain routing for each direction
// ---------------------------------------------------------------------------

struct DirectionChainTestCase {
    std::string description;
    Direction   direction;
    TableKind   table;
    std::string chain;
    Verdict     expected;
};

class DirectionChainRoutingTest
    : public ::testing::TestWithParam<DirectionChainTestCase> {};

TEST_P(DirectionChainRoutingTest, DropInCorrectChainAffectsDirection) {
    const auto& tc = GetParam();

    RuleStore store;
    Rule r; r.target.kind = Target::Kind::kDrop;
    r.matches.push_back(std::make_unique<AlwaysMatch>());
    store.append_rule(tc.table, tc.chain, std::move(r));

    TablePipeline pipeline(store);
    Packet pkt = make_tcp_packet();
    PipelineContext ctx = make_ctx(tc.direction);
    EXPECT_EQ(pipeline.process(pkt, ctx), tc.expected)
        << "Failed for: " << tc.description;
}

INSTANTIATE_TEST_SUITE_P(
    DirectionChainRouting,
    DirectionChainRoutingTest,
    ::testing::Values(
        // Chains in INBOUND flow
        DirectionChainTestCase{"INBOUND mangle/PREROUTING DROP",
            Direction::kInbound, TableKind::kMangle, "PREROUTING", Verdict::Drop},
        DirectionChainTestCase{"INBOUND nat/PREROUTING DROP",
            Direction::kInbound, TableKind::kNat, "PREROUTING", Verdict::Drop},
        DirectionChainTestCase{"INBOUND mangle/INPUT DROP",
            Direction::kInbound, TableKind::kMangle, "INPUT", Verdict::Drop},
        DirectionChainTestCase{"INBOUND filter/INPUT DROP",
            Direction::kInbound, TableKind::kFilter, "INPUT", Verdict::Drop},

        // Chains in OUTBOUND flow
        DirectionChainTestCase{"OUTBOUND mangle/OUTPUT DROP",
            Direction::kOutbound, TableKind::kMangle, "OUTPUT", Verdict::Drop},
        DirectionChainTestCase{"OUTBOUND nat/OUTPUT DROP",
            Direction::kOutbound, TableKind::kNat, "OUTPUT", Verdict::Drop},
        DirectionChainTestCase{"OUTBOUND filter/OUTPUT DROP",
            Direction::kOutbound, TableKind::kFilter, "OUTPUT", Verdict::Drop},
        DirectionChainTestCase{"OUTBOUND mangle/POSTROUTING DROP",
            Direction::kOutbound, TableKind::kMangle, "POSTROUTING", Verdict::Drop},
        DirectionChainTestCase{"OUTBOUND nat/POSTROUTING DROP",
            Direction::kOutbound, TableKind::kNat, "POSTROUTING", Verdict::Drop},

        // Chains in FORWARD flow
        DirectionChainTestCase{"FORWARD mangle/PREROUTING DROP",
            Direction::kForward, TableKind::kMangle, "PREROUTING", Verdict::Drop},
        DirectionChainTestCase{"FORWARD mangle/FORWARD DROP",
            Direction::kForward, TableKind::kMangle, "FORWARD", Verdict::Drop},
        DirectionChainTestCase{"FORWARD filter/FORWARD DROP",
            Direction::kForward, TableKind::kFilter, "FORWARD", Verdict::Drop},
        DirectionChainTestCase{"FORWARD mangle/POSTROUTING DROP",
            Direction::kForward, TableKind::kMangle, "POSTROUTING", Verdict::Drop}
    )
);

}  // namespace winiptables