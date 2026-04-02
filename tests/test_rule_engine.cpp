// test_rule_engine.cpp -- RuleEngine unit tests (Tasks 7.2-7.5)
#include <gtest/gtest.h>
#include "winiptables/rule_engine.hpp"
#include "winiptables/rule_store.hpp"
#include "winiptables/model.hpp"
#include "winiptables/packet.hpp"
#include "winiptables/imatch.hpp"
#include <memory>
#include <string>

namespace winiptables {

static Packet make_tcp_packet(uint32_t src_last = 1, uint16_t dst_port = 80) {
    Packet p;
    p.af = AddressFamily::kIPv4;
    p.src_ip.af = AddressFamily::kIPv4;
    p.src_ip.v4[0]=192; p.src_ip.v4[1]=168; p.src_ip.v4[2]=1;
    p.src_ip.v4[3]=static_cast<uint8_t>(src_last);
    p.dst_ip.af = AddressFamily::kIPv4;
    p.dst_ip.v4[0]=10; p.dst_ip.v4[1]=0; p.dst_ip.v4[2]=0; p.dst_ip.v4[3]=1;
    p.protocol = 6;
    p.src_port = 12345;
    p.dst_port = dst_port;
    p.raw_data.resize(60, 0);
    return p;
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

// Task 7.2: evaluate() basic verdict tests
TEST(RuleEngineTest, AcceptVerdict) {
    RuleStore store;
    Rule r; r.target.kind = Target::Kind::kAccept;
    r.matches.push_back(std::make_unique<AlwaysMatch>());
    store.append_rule(TableKind::kFilter, "INPUT", std::move(r));
    RuleEngine engine(store);
    Packet pkt = make_tcp_packet(); EvalContext ctx;
    EXPECT_EQ(engine.evaluate("INPUT", pkt, ctx), Verdict::Accept);
}

TEST(RuleEngineTest, DropVerdict) {
    RuleStore store;
    Rule r; r.target.kind = Target::Kind::kDrop;
    r.matches.push_back(std::make_unique<AlwaysMatch>());
    store.append_rule(TableKind::kFilter, "INPUT", std::move(r));
    RuleEngine engine(store);
    Packet pkt = make_tcp_packet(); EvalContext ctx;
    EXPECT_EQ(engine.evaluate("INPUT", pkt, ctx), Verdict::Drop);
}

TEST(RuleEngineTest, NonExistentChainDrops) {
    RuleStore store;
    RuleEngine engine(store);
    Packet pkt = make_tcp_packet(); EvalContext ctx;
    EXPECT_EQ(engine.evaluate("NONEXISTENT", pkt, ctx), Verdict::Drop);
}

// Task 7.2: Rule order invariant (Property 2)
TEST(RuleEngineTest, FirstMatchWins) {
    RuleStore store;
    {
        Rule r; r.target.kind = Target::Kind::kAccept;
        r.matches.push_back(std::make_unique<AlwaysMatch>());
        store.append_rule(TableKind::kFilter, "INPUT", std::move(r));
    }
    {
        Rule r; r.target.kind = Target::Kind::kDrop;
        r.matches.push_back(std::make_unique<AlwaysMatch>());
        store.append_rule(TableKind::kFilter, "INPUT", std::move(r));
    }
    RuleEngine engine(store);
    Packet pkt = make_tcp_packet(); EvalContext ctx;
    EXPECT_EQ(engine.evaluate("INPUT", pkt, ctx), Verdict::Accept);
}

TEST(RuleEngineTest, SkipsNonMatchingRules) {
    RuleStore store;
    {
        Rule r; r.target.kind = Target::Kind::kAccept;
        r.matches.push_back(std::make_unique<NeverMatch>());
        store.append_rule(TableKind::kFilter, "INPUT", std::move(r));
    }
    {
        Rule r; r.target.kind = Target::Kind::kDrop;
        r.matches.push_back(std::make_unique<AlwaysMatch>());
        store.append_rule(TableKind::kFilter, "INPUT", std::move(r));
    }
    RuleEngine engine(store);
    Packet pkt = make_tcp_packet(); EvalContext ctx;
    EXPECT_EQ(engine.evaluate("INPUT", pkt, ctx), Verdict::Drop);
}

// Task 7.2: JUMP target tests
TEST(RuleEngineTest, JumpToUserChainAccept) {
    RuleStore store;
    store.create_chain(TableKind::kFilter, "MY_CHAIN");
    {
        Rule r; r.target.kind = Target::Kind::kAccept;
        r.matches.push_back(std::make_unique<AlwaysMatch>());
        store.append_rule(TableKind::kFilter, "MY_CHAIN", std::move(r));
    }
    {
        Rule r; r.target.kind = Target::Kind::kJump;
        r.target.jump_chain = "MY_CHAIN";
        r.matches.push_back(std::make_unique<AlwaysMatch>());
        store.append_rule(TableKind::kFilter, "INPUT", std::move(r));
    }
    RuleEngine engine(store);
    Packet pkt = make_tcp_packet(); EvalContext ctx;
    EXPECT_EQ(engine.evaluate("INPUT", pkt, ctx), Verdict::Accept);
}

TEST(RuleEngineTest, JumpReturnContinuesParentChain) {
    RuleStore store;
    store.create_chain(TableKind::kFilter, "MY_CHAIN");
    {
        Rule r; r.target.kind = Target::Kind::kReturn;
        r.matches.push_back(std::make_unique<AlwaysMatch>());
        store.append_rule(TableKind::kFilter, "MY_CHAIN", std::move(r));
    }
    {
        Rule r; r.target.kind = Target::Kind::kJump;
        r.target.jump_chain = "MY_CHAIN";
        r.matches.push_back(std::make_unique<AlwaysMatch>());
        store.append_rule(TableKind::kFilter, "INPUT", std::move(r));
    }
    {
        Rule r; r.target.kind = Target::Kind::kDrop;
        r.matches.push_back(std::make_unique<AlwaysMatch>());
        store.append_rule(TableKind::kFilter, "INPUT", std::move(r));
    }
    RuleEngine engine(store);
    Packet pkt = make_tcp_packet(); EvalContext ctx;
    EXPECT_EQ(engine.evaluate("INPUT", pkt, ctx), Verdict::Drop);
}

// Task 7.2: Default policy tests
TEST(RuleEngineTest, DefaultPolicyUsedWhenNoMatch) {
    RuleStore store;
    store.set_policy(TableKind::kFilter, "INPUT", Target{Target::Kind::kDrop});
    RuleEngine engine(store);
    Packet pkt = make_tcp_packet(); EvalContext ctx;
    EXPECT_EQ(engine.evaluate("INPUT", pkt, ctx), Verdict::Drop);
}

TEST(RuleEngineTest, UserChainNoMatchReturnsReturn) {
    RuleStore store;
    store.create_chain(TableKind::kFilter, "MY_CHAIN");
    RuleEngine engine(store);
    Packet pkt = make_tcp_packet(); EvalContext ctx;
    EXPECT_EQ(engine.evaluate("MY_CHAIN", pkt, ctx), Verdict::Return);
}

// Task 7.3: LOG action
TEST(RuleEngineTest, LogActionWritesBuffer) {
    RuleStore store;
    {
        Rule r; r.target.kind = Target::Kind::kLog;
        r.target.log_prefix = "TEST_PREFIX";
        r.matches.push_back(std::make_unique<AlwaysMatch>());
        store.append_rule(TableKind::kFilter, "INPUT", std::move(r));
    }
    {
        Rule r; r.target.kind = Target::Kind::kAccept;
        r.matches.push_back(std::make_unique<AlwaysMatch>());
        store.append_rule(TableKind::kFilter, "INPUT", std::move(r));
    }
    RuleEngine engine(store);
    Packet pkt = make_tcp_packet(); EvalContext ctx;
    Verdict v = engine.evaluate("INPUT", pkt, ctx);
    EXPECT_EQ(v, Verdict::Accept);
    EXPECT_FALSE(ctx.log_buffer.empty());
    EXPECT_NE(ctx.log_buffer.find("TEST_PREFIX"), std::string::npos);
}

TEST(RuleEngineTest, LogActionContinuesEvaluation) {
    RuleStore store;
    {
        Rule r; r.target.kind = Target::Kind::kLog;
        r.target.log_prefix = "LOG";
        r.matches.push_back(std::make_unique<AlwaysMatch>());
        store.append_rule(TableKind::kFilter, "INPUT", std::move(r));
    }
    {
        Rule r; r.target.kind = Target::Kind::kDrop;
        r.matches.push_back(std::make_unique<AlwaysMatch>());
        store.append_rule(TableKind::kFilter, "INPUT", std::move(r));
    }
    RuleEngine engine(store);
    Packet pkt = make_tcp_packet(); EvalContext ctx;
    EXPECT_EQ(engine.evaluate("INPUT", pkt, ctx), Verdict::Drop);
    EXPECT_FALSE(ctx.log_buffer.empty());
}

// Task 7.3: REJECT action
TEST(RuleEngineTest, RejectActionSetsContext) {
    RuleStore store;
    Rule r; r.target.kind = Target::Kind::kReject;
    r.target.reject_with = IcmpType{3, 3};
    r.matches.push_back(std::make_unique<AlwaysMatch>());
    store.append_rule(TableKind::kFilter, "INPUT", std::move(r));
    RuleEngine engine(store);
    Packet pkt = make_tcp_packet(); EvalContext ctx;
    engine.evaluate("INPUT", pkt, ctx);
    EXPECT_TRUE(ctx.rejected);
    EXPECT_EQ(ctx.reject_icmp_type.type, 3);
    EXPECT_EQ(ctx.reject_icmp_type.code, 3);
}

// Task 7.3: NAT actions
TEST(RuleEngineTest, DnatActionSetsContext) {
    RuleStore store;
    Rule r; r.target.kind = Target::Kind::kDnat;
    r.target.to_addr = "192.168.1.100:8080";
    r.matches.push_back(std::make_unique<AlwaysMatch>());
    store.append_rule(TableKind::kNat, "PREROUTING", std::move(r));
    RuleEngine engine(store);
    Packet pkt = make_tcp_packet(); EvalContext ctx;
    engine.evaluate("PREROUTING", pkt, ctx);
    EXPECT_EQ(ctx.nat_dst_addr, "192.168.1.100:8080");
}

TEST(RuleEngineTest, SnatActionSetsContext) {
    RuleStore store;
    Rule r; r.target.kind = Target::Kind::kSnat;
    r.target.to_addr = "203.0.113.1";
    r.matches.push_back(std::make_unique<AlwaysMatch>());
    store.append_rule(TableKind::kNat, "POSTROUTING", std::move(r));
    RuleEngine engine(store);
    Packet pkt = make_tcp_packet(); EvalContext ctx;
    engine.evaluate("POSTROUTING", pkt, ctx);
    EXPECT_EQ(ctx.nat_src_addr, "203.0.113.1");
}

TEST(RuleEngineTest, MasqueradeActionSetsContext) {
    RuleStore store;
    Rule r; r.target.kind = Target::Kind::kMasquerade;
    r.matches.push_back(std::make_unique<AlwaysMatch>());
    store.append_rule(TableKind::kNat, "POSTROUTING", std::move(r));
    RuleEngine engine(store);
    Packet pkt = make_tcp_packet(); EvalContext ctx;
    engine.evaluate("POSTROUTING", pkt, ctx);
    EXPECT_EQ(ctx.nat_src_addr, "MASQUERADE");
}

// Task 7.4: matches_all() tests
TEST(RuleEngineTest, MatchesAllConditionsMustPass) {
    RuleStore store;
    Rule r; r.target.kind = Target::Kind::kDrop;
    r.matches.push_back(std::make_unique<AlwaysMatch>());
    r.matches.push_back(std::make_unique<NeverMatch>());
    store.append_rule(TableKind::kFilter, "INPUT", std::move(r));
    RuleEngine engine(store);
    Packet pkt = make_tcp_packet(); EvalContext ctx;
    EXPECT_EQ(engine.evaluate("INPUT", pkt, ctx), Verdict::Accept);
}

TEST(RuleEngineTest, EmptyMatchListAlwaysMatches) {
    RuleStore store;
    Rule r; r.target.kind = Target::Kind::kDrop;
    store.append_rule(TableKind::kFilter, "INPUT", std::move(r));
    RuleEngine engine(store);
    Packet pkt = make_tcp_packet(); EvalContext ctx;
    EXPECT_EQ(engine.evaluate("INPUT", pkt, ctx), Verdict::Drop);
}

// Task 7.5: Counter increment tests (atomic operations)
TEST(RuleEngineTest, CounterIncrementedOnMatch) {
    RuleStore store;
    Rule r; r.target.kind = Target::Kind::kAccept;
    r.matches.push_back(std::make_unique<AlwaysMatch>());
    store.append_rule(TableKind::kFilter, "INPUT", std::move(r));
    RuleEngine engine(store);
    Packet pkt = make_tcp_packet(); pkt.raw_data.resize(100, 0);
    EvalContext ctx; engine.evaluate("INPUT", pkt, ctx);
    const Chain* chain = store.get_chain(TableKind::kFilter, "INPUT");
    ASSERT_NE(chain, nullptr); ASSERT_FALSE(chain->rules.empty());
    const Rule& rule = *chain->rules.front();
    EXPECT_EQ(rule.counters.packets.load(), 1u);
    EXPECT_EQ(rule.counters.bytes.load(), 100u);
}

TEST(RuleEngineTest, CounterNotIncrementedOnNoMatch) {
    RuleStore store;
    Rule r; r.target.kind = Target::Kind::kDrop;
    r.matches.push_back(std::make_unique<NeverMatch>());
    store.append_rule(TableKind::kFilter, "INPUT", std::move(r));
    RuleEngine engine(store);
    Packet pkt = make_tcp_packet(); EvalContext ctx;
    engine.evaluate("INPUT", pkt, ctx);
    const Chain* chain = store.get_chain(TableKind::kFilter, "INPUT");
    ASSERT_NE(chain, nullptr); ASSERT_FALSE(chain->rules.empty());
    const Rule& rule = *chain->rules.front();
    EXPECT_EQ(rule.counters.packets.load(), 0u);
    EXPECT_EQ(rule.counters.bytes.load(), 0u);
}

TEST(RuleEngineTest, CounterMonotonicallyIncreasing) {
    RuleStore store;
    Rule r; r.target.kind = Target::Kind::kAccept;
    r.matches.push_back(std::make_unique<AlwaysMatch>());
    store.append_rule(TableKind::kFilter, "INPUT", std::move(r));
    RuleEngine engine(store);
    Packet pkt = make_tcp_packet(); pkt.raw_data.resize(50, 0);
    const Chain* chain = store.get_chain(TableKind::kFilter, "INPUT");
    ASSERT_NE(chain, nullptr);
    const Rule& rule = *chain->rules.front();
    uint64_t prev_p = 0, prev_b = 0;
    for (int i = 0; i < 5; ++i) {
        EvalContext ctx; engine.evaluate("INPUT", pkt, ctx);
        uint64_t cp = rule.counters.packets.load();
        uint64_t cb = rule.counters.bytes.load();
        EXPECT_GE(cp, prev_p); EXPECT_GE(cb, prev_b);
        prev_p = cp; prev_b = cb;
    }
    EXPECT_EQ(rule.counters.packets.load(), 5u);
    EXPECT_EQ(rule.counters.bytes.load(), 250u);
}


// =============================================================================
// Task 7.6: Property tests
// =============================================================================

// ---------------------------------------------------------------------------
// Helper: Port match (used to construct selective matching conditions in property tests)
// ---------------------------------------------------------------------------
class PortMatch : public IMatch {
public:
    explicit PortMatch(uint16_t port) : port_(port) {}
    bool Matches(const Packet& pkt, const MatchContext&) const override {
        return pkt.dst_port == port_;
    }
    std::string ToRuleText() const override {
        return "--dport " + std::to_string(port_);
    }
private:
    uint16_t port_;
};

// ---------------------------------------------------------------------------
// Property 2: Rule order invariant
// Validates: Requirements 4.8
//
// forall packet, chain: evaluate(chain, packet) == evaluate_first_match(chain, packet)
//
// Reference implementation evaluate_first_match: linear scan of chain rules, return verdict of first matching rule.
// If evaluate() matches the reference implementation, the property holds.
// ---------------------------------------------------------------------------

// Parameterized test case: describes a chain's rule sequence and expected verdict
struct RuleOrderTestCase {
    std::string description;
    // Each rule: (matches, target kind)
    std::vector<std::pair<bool, Target::Kind>> rules;
    Verdict expected_verdict;
};

class RuleOrderInvariantTest
    : public ::testing::TestWithParam<RuleOrderTestCase> {};

// Reference implementation: linear scan, return verdict of first matching rule (no JUMP/RETURN support, for simple chains only)
// Note: This function is for documentation purposes, illustrating Property 2's semantic equivalence
// evaluate(chain, packet) == evaluate_first_match_simple(rules, default_policy)
[[maybe_unused]]
static Verdict evaluate_first_match_simple(
    const std::vector<std::pair<bool, Target::Kind>>& rules,
    Target::Kind default_policy_kind = Target::Kind::kDrop)
{
    for (const auto& [matches, kind] : rules) {
        if (!matches) continue;
        switch (kind) {
            case Target::Kind::kAccept: return Verdict::Accept;
            case Target::Kind::kDrop:   return Verdict::Drop;
            case Target::Kind::kReturn: return Verdict::Return;
            default: break;
        }
    }
    return (default_policy_kind == Target::Kind::kAccept)
               ? Verdict::Accept
               : Verdict::Drop;
}

TEST_P(RuleOrderInvariantTest, EvaluateMatchesFirstMatchSemantics) {
    const auto& tc = GetParam();

    RuleStore store;
    for (const auto& [should_match, kind] : tc.rules) {
        Rule r;
        r.target.kind = kind;
        if (should_match)
            r.matches.push_back(std::make_unique<AlwaysMatch>());
        else
            r.matches.push_back(std::make_unique<NeverMatch>());
        store.append_rule(TableKind::kFilter, "INPUT", std::move(r));
    }

    RuleEngine engine(store);
    Packet pkt = make_tcp_packet();
    EvalContext ctx;
    Verdict actual = engine.evaluate("INPUT", pkt, ctx);

    EXPECT_EQ(actual, tc.expected_verdict)
        << "Failed for case: " << tc.description;
}

INSTANTIATE_TEST_SUITE_P(
    Property2RuleOrderInvariant,
    RuleOrderInvariantTest,
    ::testing::Values(
        RuleOrderTestCase{
            "single matching ACCEPT",
            {{true, Target::Kind::kAccept}},
            Verdict::Accept
        },
        RuleOrderTestCase{
            "single matching DROP",
            {{true, Target::Kind::kDrop}},
            Verdict::Drop
        },
        RuleOrderTestCase{
            "first no-match then ACCEPT",
            {{false, Target::Kind::kDrop}, {true, Target::Kind::kAccept}},
            Verdict::Accept
        },
        RuleOrderTestCase{
            "first no-match then DROP",
            {{false, Target::Kind::kAccept}, {true, Target::Kind::kDrop}},
            Verdict::Drop
        },
        RuleOrderTestCase{
            "ACCEPT before DROP -- first match wins",
            {{true, Target::Kind::kAccept}, {true, Target::Kind::kDrop}},
            Verdict::Accept
        },
        RuleOrderTestCase{
            "DROP before ACCEPT -- first match wins",
            {{true, Target::Kind::kDrop}, {true, Target::Kind::kAccept}},
            Verdict::Drop
        },
        RuleOrderTestCase{
            "multiple non-matching then ACCEPT",
            {{false, Target::Kind::kDrop},
             {false, Target::Kind::kDrop},
             {false, Target::Kind::kDrop},
             {true,  Target::Kind::kAccept}},
            Verdict::Accept
        },
        RuleOrderTestCase{
            "multiple non-matching then DROP",
            {{false, Target::Kind::kAccept},
             {false, Target::Kind::kAccept},
             {true,  Target::Kind::kDrop}},
            Verdict::Drop
        },
        RuleOrderTestCase{
            "LOG then ACCEPT -- LOG is non-terminal",
            {{true, Target::Kind::kLog}, {true, Target::Kind::kAccept}},
            Verdict::Accept
        },
        RuleOrderTestCase{
            "LOG then DROP -- LOG is non-terminal",
            {{true, Target::Kind::kLog}, {true, Target::Kind::kDrop}},
            Verdict::Drop
        },
        RuleOrderTestCase{
            "no match uses default ACCEPT policy (INPUT default)",
            {{false, Target::Kind::kDrop}, {false, Target::Kind::kDrop}},
            Verdict::Accept
        }
    )
);

// Property 2 extension: verify order invariant with different packets (ports)
// Chain: rule 1 matches port 80 -> ACCEPT, rule 2 matches all -> DROP
// Port 80 packets should ACCEPT, other ports should DROP
struct PacketVariantTestCase {
    std::string description;
    uint16_t    dst_port;
    Verdict     expected;
};

class RuleOrderPacketVariantTest
    : public ::testing::TestWithParam<PacketVariantTestCase> {};

TEST_P(RuleOrderPacketVariantTest, FirstMatchDeterminesVerdict) {
    const auto& tc = GetParam();

    RuleStore store;
    // Rule 1: matches port 80 -> ACCEPT
    {
        Rule r;
        r.target.kind = Target::Kind::kAccept;
        r.matches.push_back(std::make_unique<PortMatch>(80));
        store.append_rule(TableKind::kFilter, "INPUT", std::move(r));
    }
    // Rule 2: matches all -> DROP
    {
        Rule r;
        r.target.kind = Target::Kind::kDrop;
        r.matches.push_back(std::make_unique<AlwaysMatch>());
        store.append_rule(TableKind::kFilter, "INPUT", std::move(r));
    }

    RuleEngine engine(store);
    Packet pkt = make_tcp_packet(1, tc.dst_port);
    EvalContext ctx;
    EXPECT_EQ(engine.evaluate("INPUT", pkt, ctx), tc.expected)
        << "Failed for: " << tc.description;
}

INSTANTIATE_TEST_SUITE_P(
    Property2PacketVariants,
    RuleOrderPacketVariantTest,
    ::testing::Values(
        PacketVariantTestCase{"port 80 matches rule 1 ACCEPT",  80,   Verdict::Accept},
        PacketVariantTestCase{"port 443 falls through to DROP",  443,  Verdict::Drop},
        PacketVariantTestCase{"port 22 falls through to DROP",   22,   Verdict::Drop},
        PacketVariantTestCase{"port 8080 falls through to DROP", 8080, Verdict::Drop},
        PacketVariantTestCase{"port 1 falls through to DROP",    1,    Verdict::Drop},
        PacketVariantTestCase{"port 65535 falls through to DROP",65535,Verdict::Drop}
    )
);

// ---------------------------------------------------------------------------
// Property 4: Counter monotonically increasing invariant
// Validates: Requirements 9.2
//
// forall rule: counter_after >= counter_before
//
// Parameterized test with various packet sizes and evaluation counts.
// ---------------------------------------------------------------------------

struct CounterMonotonicTestCase {
    std::string description;
    std::vector<std::size_t> packet_sizes;
    uint64_t expected_packets;
    uint64_t expected_bytes;
};

class CounterMonotonicTest
    : public ::testing::TestWithParam<CounterMonotonicTestCase> {};

TEST_P(CounterMonotonicTest, CountersNeverDecrease) {
    const auto& tc = GetParam();

    RuleStore store;
    Rule r;
    r.target.kind = Target::Kind::kAccept;
    r.matches.push_back(std::make_unique<AlwaysMatch>());
    store.append_rule(TableKind::kFilter, "INPUT", std::move(r));

    RuleEngine engine(store);
    const Chain* chain = store.get_chain(TableKind::kFilter, "INPUT");
    ASSERT_NE(chain, nullptr);
    ASSERT_FALSE(chain->rules.empty());
    const Rule& rule = *chain->rules.front();

    uint64_t prev_packets = 0;
    uint64_t prev_bytes   = 0;

    for (std::size_t sz : tc.packet_sizes) {
        Packet pkt = make_tcp_packet();
        pkt.raw_data.resize(sz, 0xAB);

        EvalContext ctx;
        engine.evaluate("INPUT", pkt, ctx);

        uint64_t cur_packets = rule.counters.packets.load(std::memory_order_relaxed);
        uint64_t cur_bytes   = rule.counters.bytes.load(std::memory_order_relaxed);

        // Property 4: counters can only increase
        EXPECT_GE(cur_packets, prev_packets)
            << tc.description << ": packets counter decreased!";
        EXPECT_GE(cur_bytes, prev_bytes)
            << tc.description << ": bytes counter decreased!";

        prev_packets = cur_packets;
        prev_bytes   = cur_bytes;
    }

    // Final value verification
    EXPECT_EQ(rule.counters.packets.load(), tc.expected_packets)
        << tc.description;
    EXPECT_EQ(rule.counters.bytes.load(), tc.expected_bytes)
        << tc.description;
}

INSTANTIATE_TEST_SUITE_P(
    Property4CounterMonotonic,
    CounterMonotonicTest,
    ::testing::Values(
        CounterMonotonicTestCase{
            "single packet 60 bytes",
            {60},
            1, 60
        },
        CounterMonotonicTestCase{
            "three equal packets 100 bytes each",
            {100, 100, 100},
            3, 300
        },
        CounterMonotonicTestCase{
            "varying packet sizes",
            {40, 100, 1500, 64, 512},
            5, 40 + 100 + 1500 + 64 + 512
        },
        CounterMonotonicTestCase{
            "minimum size packets",
            {1, 1, 1, 1, 1},
            5, 5
        },
        CounterMonotonicTestCase{
            "large packets",
            {65535, 65535},
            2, 65535 * 2
        },
        CounterMonotonicTestCase{
            "ten packets ascending sizes",
            {10, 20, 30, 40, 50, 60, 70, 80, 90, 100},
            10, 550
        },
        CounterMonotonicTestCase{
            "zero-size packets (empty raw_data)",
            {0, 0, 0},
            3, 0
        }
    )
);

// Property 4 extension: non-matching rules' counters should not increase
TEST(CounterMonotonicExtTest, NonMatchingRuleCounterStaysZero) {
    RuleStore store;
    Rule r;
    r.target.kind = Target::Kind::kDrop;
    r.matches.push_back(std::make_unique<NeverMatch>());
    store.append_rule(TableKind::kFilter, "INPUT", std::move(r));

    RuleEngine engine(store);
    const Chain* chain = store.get_chain(TableKind::kFilter, "INPUT");
    ASSERT_NE(chain, nullptr);
    const Rule& rule = *chain->rules.front();

    for (int i = 0; i < 10; ++i) {
        Packet pkt = make_tcp_packet();
        pkt.raw_data.resize(100, 0);
        EvalContext ctx;
        engine.evaluate("INPUT", pkt, ctx);

        // Non-matching rule counter stays at 0 (monotonically increasing but never increases)
        EXPECT_EQ(rule.counters.packets.load(), 0u);
        EXPECT_EQ(rule.counters.bytes.load(), 0u);
    }
}

// Property 4 extension: multiple rules, only matched rule counter increases
TEST(CounterMonotonicExtTest, OnlyMatchedRuleCounterIncreases) {
    RuleStore store;
    // Rule 1: matches port 80 -> ACCEPT
    {
        Rule r;
        r.target.kind = Target::Kind::kAccept;
        r.matches.push_back(std::make_unique<PortMatch>(80));
        store.append_rule(TableKind::kFilter, "INPUT", std::move(r));
    }
    // Rule 2: matches all -> DROP
    {
        Rule r;
        r.target.kind = Target::Kind::kDrop;
        r.matches.push_back(std::make_unique<AlwaysMatch>());
        store.append_rule(TableKind::kFilter, "INPUT", std::move(r));
    }

    RuleEngine engine(store);
    const Chain* chain = store.get_chain(TableKind::kFilter, "INPUT");
    ASSERT_NE(chain, nullptr);
    auto it = chain->rules.begin();
    const Rule& rule1 = **it++;
    const Rule& rule2 = **it;

    // Send 3 packets with port 80 (hits rule 1)
    for (int i = 0; i < 3; ++i) {
        Packet pkt = make_tcp_packet(1, 80);
        pkt.raw_data.resize(50, 0);
        EvalContext ctx;
        engine.evaluate("INPUT", pkt, ctx);
    }
    // Send 2 packets with port 443 (hits rule 2)
    for (int i = 0; i < 2; ++i) {
        Packet pkt = make_tcp_packet(1, 443);
        pkt.raw_data.resize(50, 0);
        EvalContext ctx;
        engine.evaluate("INPUT", pkt, ctx);
    }

    // Rule 1: 3 hits, counter monotonically increasing
    EXPECT_EQ(rule1.counters.packets.load(), 3u);
    EXPECT_EQ(rule1.counters.bytes.load(), 150u);

    // Rule 2: 2 hits, counter monotonically increasing
    EXPECT_EQ(rule2.counters.packets.load(), 2u);
    EXPECT_EQ(rule2.counters.bytes.load(), 100u);
}

} // namespace winiptables