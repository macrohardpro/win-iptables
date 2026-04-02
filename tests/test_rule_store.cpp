// test_rule_store.cpp -- RuleStore unit tests (Task 6.6)
#include "winiptables/rule_store.hpp"
#include "winiptables/imatch.hpp"
#include <gtest/gtest.h>
#include <atomic>
#include <iterator>
#include <thread>
#include <vector>

using namespace winiptables;

// ---------------------------------------------------------------------------
// Helper: construct a simple rule
// ---------------------------------------------------------------------------
static Rule make_rule(Target::Kind kind = Target::Kind::kAccept) {
    Rule r;
    r.target.kind = kind;
    return r;
}

// ---------------------------------------------------------------------------
// Initialization: builtin tables and chains
// ---------------------------------------------------------------------------

TEST(RuleStoreInit, FilterTableHasBuiltinChains) {
    RuleStore store;
    auto chains = store.list_chains(TableKind::kFilter);
    std::vector<std::string> names;
    for (const Chain* c : chains) names.push_back(c->name);
    EXPECT_TRUE(std::find(names.begin(), names.end(), "INPUT")   != names.end());
    EXPECT_TRUE(std::find(names.begin(), names.end(), "OUTPUT")  != names.end());
    EXPECT_TRUE(std::find(names.begin(), names.end(), "FORWARD") != names.end());
}

TEST(RuleStoreInit, NatTableHasBuiltinChains) {
    RuleStore store;
    auto chains = store.list_chains(TableKind::kNat);
    std::vector<std::string> names;
    for (const Chain* c : chains) names.push_back(c->name);
    EXPECT_TRUE(std::find(names.begin(), names.end(), "PREROUTING")  != names.end());
    EXPECT_TRUE(std::find(names.begin(), names.end(), "OUTPUT")      != names.end());
    EXPECT_TRUE(std::find(names.begin(), names.end(), "POSTROUTING") != names.end());
}

TEST(RuleStoreInit, MangleTableHasFiveBuiltinChains) {
    RuleStore store;
    auto chains = store.list_chains(TableKind::kMangle);
    EXPECT_EQ(chains.size(), 5u);
}

TEST(RuleStoreInit, BuiltinChainsHavePolicy) {
    RuleStore store;
    const Chain* input = store.get_chain(TableKind::kFilter, "INPUT");
    ASSERT_NE(input, nullptr);
    EXPECT_TRUE(input->policy.has_value());
}

// ---------------------------------------------------------------------------
// Chain name validation
// ---------------------------------------------------------------------------

TEST(ChainNameValidation, ValidNames) {
    EXPECT_TRUE(RuleStore::is_valid_chain_name("MY-CHAIN"));
    EXPECT_TRUE(RuleStore::is_valid_chain_name("chain_1"));
    EXPECT_TRUE(RuleStore::is_valid_chain_name("A"));
    EXPECT_TRUE(RuleStore::is_valid_chain_name(std::string(29, 'a')));
}

TEST(ChainNameValidation, InvalidNames) {
    EXPECT_FALSE(RuleStore::is_valid_chain_name(""));
    EXPECT_FALSE(RuleStore::is_valid_chain_name(std::string(30, 'a')));
    EXPECT_FALSE(RuleStore::is_valid_chain_name("bad name"));
    EXPECT_FALSE(RuleStore::is_valid_chain_name("bad.name"));
}

// ---------------------------------------------------------------------------
// Task 6.3: Chain management
// ---------------------------------------------------------------------------

TEST(CreateChain, SuccessCreatesChain) {
    RuleStore store;
    auto res = store.create_chain(TableKind::kFilter, "MY_CHAIN");
    EXPECT_TRUE(res.ok);
    EXPECT_NE(store.get_chain(TableKind::kFilter, "MY_CHAIN"), nullptr);
}

TEST(CreateChain, DuplicateReturnsError) {
    RuleStore store;
    store.create_chain(TableKind::kFilter, "MY_CHAIN");
    auto res = store.create_chain(TableKind::kFilter, "MY_CHAIN");
    EXPECT_FALSE(res.ok);
    EXPECT_EQ(res.message, "Chain already exists");
}

TEST(CreateChain, InvalidNameReturnsError) {
    RuleStore store;
    auto res = store.create_chain(TableKind::kFilter, "bad name!");
    EXPECT_FALSE(res.ok);
}

TEST(DeleteChain, SuccessDeletesEmptyChain) {
    RuleStore store;
    store.create_chain(TableKind::kFilter, "TMP");
    auto res = store.delete_chain(TableKind::kFilter, "TMP");
    EXPECT_TRUE(res.ok);
    EXPECT_EQ(store.get_chain(TableKind::kFilter, "TMP"), nullptr);
}

TEST(DeleteChain, CannotDeleteBuiltinChain) {
    RuleStore store;
    auto res = store.delete_chain(TableKind::kFilter, "INPUT");
    EXPECT_FALSE(res.ok);
}

TEST(DeleteChain, CannotDeleteNonEmptyChain) {
    RuleStore store;
    store.create_chain(TableKind::kFilter, "TMP");
    store.append_rule(TableKind::kFilter, "TMP", make_rule());
    auto res = store.delete_chain(TableKind::kFilter, "TMP");
    EXPECT_FALSE(res.ok);
}

TEST(DeleteChain, CannotDeleteReferencedChain) {
    RuleStore store;
    store.create_chain(TableKind::kFilter, "TMP");
    Rule r;
    r.target.kind       = Target::Kind::kJump;
    r.target.jump_chain = "TMP";
    store.append_rule(TableKind::kFilter, "INPUT", std::move(r));
    auto res = store.delete_chain(TableKind::kFilter, "TMP");
    EXPECT_FALSE(res.ok);
}

TEST(SetPolicy, SuccessOnBuiltinChain) {
    RuleStore store;
    Target drop;
    drop.kind = Target::Kind::kDrop;
    auto res = store.set_policy(TableKind::kFilter, "INPUT", drop);
    EXPECT_TRUE(res.ok);
    const Chain* c = store.get_chain(TableKind::kFilter, "INPUT");
    ASSERT_NE(c, nullptr);
    ASSERT_TRUE(c->policy.has_value());
    EXPECT_EQ(c->policy->kind, Target::Kind::kDrop);
}

TEST(SetPolicy, FailsOnUserChain) {
    RuleStore store;
    store.create_chain(TableKind::kFilter, "USER");
    Target accept;
    accept.kind = Target::Kind::kAccept;
    auto res = store.set_policy(TableKind::kFilter, "USER", accept);
    EXPECT_FALSE(res.ok);
}

TEST(RenameChain, SuccessRenamesUserChain) {
    RuleStore store;
    store.create_chain(TableKind::kFilter, "OLD");
    auto res = store.rename_chain(TableKind::kFilter, "OLD", "NEW");
    EXPECT_TRUE(res.ok);
    EXPECT_EQ(store.get_chain(TableKind::kFilter, "OLD"), nullptr);
    EXPECT_NE(store.get_chain(TableKind::kFilter, "NEW"), nullptr);
}

TEST(RenameChain, FailsOnBuiltinChain) {
    RuleStore store;
    auto res = store.rename_chain(TableKind::kFilter, "INPUT", "NEWINPUT");
    EXPECT_FALSE(res.ok);
}

TEST(RenameChain, FailsIfNewNameExists) {
    RuleStore store;
    store.create_chain(TableKind::kFilter, "A");
    store.create_chain(TableKind::kFilter, "B");
    auto res = store.rename_chain(TableKind::kFilter, "A", "B");
    EXPECT_FALSE(res.ok);
}

// ---------------------------------------------------------------------------
// Task 6.4: Rule management
// ---------------------------------------------------------------------------

TEST(AppendRule, AppendsToEnd) {
    RuleStore store;
    store.append_rule(TableKind::kFilter, "INPUT", make_rule(Target::Kind::kAccept));
    store.append_rule(TableKind::kFilter, "INPUT", make_rule(Target::Kind::kDrop));
    const Chain* c = store.get_chain(TableKind::kFilter, "INPUT");
    ASSERT_NE(c, nullptr);
    ASSERT_EQ(c->rules.size(), 2u);
    auto it = c->rules.begin();
    EXPECT_EQ((*it)->target.kind, Target::Kind::kAccept);
    ++it;
    EXPECT_EQ((*it)->target.kind, Target::Kind::kDrop);
}

TEST(InsertRule, InsertsAtPosition1ByDefault) {
    RuleStore store;
    store.append_rule(TableKind::kFilter, "INPUT", make_rule(Target::Kind::kDrop));
    store.insert_rule(TableKind::kFilter, "INPUT", make_rule(Target::Kind::kAccept));
    const Chain* c = store.get_chain(TableKind::kFilter, "INPUT");
    ASSERT_EQ(c->rules.size(), 2u);
    auto it = c->rules.begin();
    EXPECT_EQ((*it)->target.kind, Target::Kind::kAccept);
    ++it;
    EXPECT_EQ((*it)->target.kind, Target::Kind::kDrop);
}

TEST(InsertRule, InsertsAtSpecifiedPosition) {
    RuleStore store;
    store.append_rule(TableKind::kFilter, "INPUT", make_rule(Target::Kind::kAccept));
    store.append_rule(TableKind::kFilter, "INPUT", make_rule(Target::Kind::kDrop));
    store.insert_rule(TableKind::kFilter, "INPUT", make_rule(Target::Kind::kReturn), 2);
    const Chain* c = store.get_chain(TableKind::kFilter, "INPUT");
    ASSERT_EQ(c->rules.size(), 3u);
    auto it = std::next(c->rules.begin(), 1);
    EXPECT_EQ((*it)->target.kind, Target::Kind::kReturn);
}

TEST(InsertRule, InvalidPositionReturnsError) {
    RuleStore store;
    auto res = store.insert_rule(TableKind::kFilter, "INPUT",
                                  make_rule(), 99);
    EXPECT_FALSE(res.ok);
}

TEST(DeleteRuleByNum, DeletesCorrectRule) {
    RuleStore store;
    store.append_rule(TableKind::kFilter, "INPUT", make_rule(Target::Kind::kAccept));
    store.append_rule(TableKind::kFilter, "INPUT", make_rule(Target::Kind::kDrop));
    auto res = store.delete_rule_by_num(TableKind::kFilter, "INPUT", 1);
    EXPECT_TRUE(res.ok);
    const Chain* c = store.get_chain(TableKind::kFilter, "INPUT");
    ASSERT_EQ(c->rules.size(), 1u);
    EXPECT_EQ(c->rules.front()->target.kind, Target::Kind::kDrop);
}

TEST(DeleteRuleByNum, InvalidNumReturnsError) {
    RuleStore store;
    auto res = store.delete_rule_by_num(TableKind::kFilter, "INPUT", 1);
    EXPECT_FALSE(res.ok);
}

TEST(DeleteRuleBySpec, DeletesFirstMatch) {
    RuleStore store;
    store.append_rule(TableKind::kFilter, "INPUT", make_rule(Target::Kind::kAccept));
    store.append_rule(TableKind::kFilter, "INPUT", make_rule(Target::Kind::kDrop));
    auto res = store.delete_rule_by_spec(
        TableKind::kFilter, "INPUT",
        [](const Rule& r) { return r.target.kind == Target::Kind::kAccept; });
    EXPECT_TRUE(res.ok);
    const Chain* c = store.get_chain(TableKind::kFilter, "INPUT");
    ASSERT_EQ(c->rules.size(), 1u);
    EXPECT_EQ(c->rules.front()->target.kind, Target::Kind::kDrop);
}

TEST(DeleteRuleBySpec, NoMatchReturnsError) {
    RuleStore store;
    auto res = store.delete_rule_by_spec(
        TableKind::kFilter, "INPUT",
        [](const Rule&) { return false; });
    EXPECT_FALSE(res.ok);
    EXPECT_EQ(res.message, "Bad rule (does not exist)");
}

TEST(ReplaceRule, ReplacesAtPosition) {
    RuleStore store;
    store.append_rule(TableKind::kFilter, "INPUT", make_rule(Target::Kind::kAccept));
    auto res = store.replace_rule(TableKind::kFilter, "INPUT", 1,
                                   make_rule(Target::Kind::kDrop));
    EXPECT_TRUE(res.ok);
    const Chain* c = store.get_chain(TableKind::kFilter, "INPUT");
    ASSERT_EQ(c->rules.size(), 1u);
    EXPECT_EQ(c->rules.front()->target.kind, Target::Kind::kDrop);
}

TEST(ReplaceRule, InvalidPositionReturnsError) {
    RuleStore store;
    auto res = store.replace_rule(TableKind::kFilter, "INPUT", 5,
                                   make_rule());
    EXPECT_FALSE(res.ok);
}

// ---------------------------------------------------------------------------
// Task 6.5: Counter operations
// ---------------------------------------------------------------------------

TEST(ZeroCounters, ZerosSingleChain) {
    RuleStore store;
    store.append_rule(TableKind::kFilter, "INPUT", make_rule());
    auto res = store.zero_counters(TableKind::kFilter, "INPUT");
    EXPECT_TRUE(res.ok);
}

TEST(ZeroCounters, ZerosAllChainsInTable) {
    RuleStore store;
    store.append_rule(TableKind::kFilter, "INPUT",   make_rule());
    store.append_rule(TableKind::kFilter, "OUTPUT",  make_rule());
    store.append_rule(TableKind::kFilter, "FORWARD", make_rule());
    auto res = store.zero_counters(TableKind::kFilter);
    EXPECT_TRUE(res.ok);
}

TEST(ZeroCounters, InvalidChainReturnsError) {
    RuleStore store;
    auto res = store.zero_counters(TableKind::kFilter, "NONEXISTENT");
    EXPECT_FALSE(res.ok);
}

// ---------------------------------------------------------------------------
// Concurrency safety tests
// ---------------------------------------------------------------------------

TEST(Concurrency, ConcurrentAppendAndList) {
    RuleStore store;
    constexpr int kThreads = 8;
    constexpr int kRulesPerThread = 50;

    std::vector<std::thread> writers;
    writers.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i) {
        writers.emplace_back([&store, kRulesPerThread]() {
            for (int j = 0; j < kRulesPerThread; ++j)
                store.append_rule(TableKind::kFilter, "INPUT", make_rule());
        });
    }

    std::vector<std::thread> readers;
    readers.reserve(4);
    for (int i = 0; i < 4; ++i) {
        readers.emplace_back([&store]() {
            for (int j = 0; j < 20; ++j)
                (void)store.list_chains(TableKind::kFilter);
        });
    }

    for (auto& t : writers) t.join();
    for (auto& t : readers) t.join();

    const Chain* c = store.get_chain(TableKind::kFilter, "INPUT");
    ASSERT_NE(c, nullptr);
    EXPECT_EQ(c->rules.size(), static_cast<size_t>(kThreads * kRulesPerThread));
}

TEST(Concurrency, ConcurrentChainCreation) {
    RuleStore store;
    constexpr int kThreads = 16;

    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    std::vector<StoreResult> results(kThreads, StoreResult::Err("not run"));

    for (int i = 0; i < kThreads; ++i) {
        threads.emplace_back([&store, &results, i]() {
            std::string name = "CHAIN_" + std::to_string(i);
            results[i] = store.create_chain(TableKind::kFilter, name);
        });
    }
    for (auto& t : threads) t.join();

    for (int i = 0; i < kThreads; ++i) {
        EXPECT_TRUE(results[i].ok) << "Thread " << i << " failed: " << results[i].message;
        std::string name = "CHAIN_" + std::to_string(i);
        EXPECT_NE(store.get_chain(TableKind::kFilter, name), nullptr)
            << "Chain " << name << " not found after concurrent creation";
    }

    auto chains = store.list_chains(TableKind::kFilter);
    EXPECT_EQ(chains.size(), static_cast<size_t>(3 + kThreads));
}

TEST(Concurrency, ConcurrentChainCreationDuplicate) {
    RuleStore store;
    constexpr int kThreads = 8;

    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    std::vector<StoreResult> results(kThreads, StoreResult::Err("not run"));

    for (int i = 0; i < kThreads; ++i) {
        threads.emplace_back([&store, &results, i]() {
            results[i] = store.create_chain(TableKind::kFilter, "RACE_CHAIN");
        });
    }
    for (auto& t : threads) t.join();

    int success_count = 0;
    for (int i = 0; i < kThreads; ++i) {
        if (results[i].ok) ++success_count;
    }
    EXPECT_EQ(success_count, 1) << "Exactly one thread should win the race";
    EXPECT_NE(store.get_chain(TableKind::kFilter, "RACE_CHAIN"), nullptr);
}

TEST(Concurrency, ConcurrentRuleDeletion) {
    RuleStore store;
    constexpr int kRules = 20;

    for (int i = 0; i < kRules; ++i)
        store.append_rule(TableKind::kFilter, "INPUT", make_rule());

    std::vector<std::thread> threads;
    threads.reserve(kRules);
    std::vector<StoreResult> results(kRules, StoreResult::Err("not run"));

    for (int i = 0; i < kRules; ++i) {
        threads.emplace_back([&store, &results, i]() {
            results[i] = store.delete_rule_by_num(TableKind::kFilter, "INPUT", 1);
        });
    }
    for (auto& t : threads) t.join();

    int success_count = 0;
    for (int i = 0; i < kRules; ++i) {
        if (results[i].ok) ++success_count;
    }
    EXPECT_EQ(success_count, kRules);

    const Chain* c = store.get_chain(TableKind::kFilter, "INPUT");
    ASSERT_NE(c, nullptr);
    EXPECT_EQ(c->rules.size(), 0u);
}

TEST(Concurrency, ConcurrentMixedWriters) {
    RuleStore store;
    constexpr int kAppenders = 6;
    constexpr int kDeleters  = 4;
    constexpr int kRulesPerAppender = 10;

    std::vector<std::thread> threads;
    threads.reserve(kAppenders + kDeleters);

    std::atomic<int> delete_successes{0};

    for (int i = 0; i < kAppenders; ++i) {
        threads.emplace_back([&store, kRulesPerAppender]() {
            for (int j = 0; j < kRulesPerAppender; ++j)
                store.append_rule(TableKind::kFilter, "FORWARD", make_rule());
        });
    }
    for (int i = 0; i < kDeleters; ++i) {
        threads.emplace_back([&store, &delete_successes]() {
            for (int j = 0; j < 5; ++j) {
                auto res = store.delete_rule_by_num(TableKind::kFilter, "FORWARD", 1);
                if (res.ok) ++delete_successes;
            }
        });
    }

    for (auto& t : threads) t.join();

    const Chain* c = store.get_chain(TableKind::kFilter, "FORWARD");
    ASSERT_NE(c, nullptr);
    int expected = kAppenders * kRulesPerAppender - delete_successes.load();
    EXPECT_EQ(static_cast<int>(c->rules.size()), expected);
}