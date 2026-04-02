// Copyright (c) winiptables authors. All rights reserved.
// test_model.cpp -- Core data model unit tests

#include <gtest/gtest.h>

#include "winiptables/imatch.hpp"
#include "winiptables/model.hpp"

#include <thread>
#include <vector>

using namespace winiptables;

// ── RuleCounters ──────────────────────────────────────────────────────────────

TEST(RuleCounters, InitialValuesAreZero) {
  RuleCounters c;
  EXPECT_EQ(c.packets.load(), 0u);
  EXPECT_EQ(c.bytes.load(), 0u);
}

TEST(RuleCounters, IncrementUpdatesPacketsAndBytes) {
  RuleCounters c;
  c.Increment(100);
  EXPECT_EQ(c.packets.load(), 1u);
  EXPECT_EQ(c.bytes.load(), 100u);
}

TEST(RuleCounters, MultipleIncrementsAccumulate) {
  RuleCounters c;
  c.Increment(50);
  c.Increment(200);
  c.Increment(10);
  EXPECT_EQ(c.packets.load(), 3u);
  EXPECT_EQ(c.bytes.load(), 260u);
}

TEST(RuleCounters, AtomicIncrementFromMultipleThreads) {
  RuleCounters c;
  constexpr int kThreads = 8;
  constexpr int kIter    = 1000;

  std::vector<std::thread> threads;
  threads.reserve(kThreads);
  for (int i = 0; i < kThreads; ++i) {
    threads.emplace_back([&c, kIter]() {
      for (int j = 0; j < kIter; ++j) c.Increment(1);
    });
  }
  for (auto& t : threads) t.join();

  EXPECT_EQ(c.packets.load(), static_cast<uint64_t>(kThreads * kIter));
  EXPECT_EQ(c.bytes.load(),   static_cast<uint64_t>(kThreads * kIter));
}

TEST(RuleCounters, ResetClearsCounters) {
  RuleCounters c;
  c.Increment(100);
  c.Reset();
  EXPECT_EQ(c.packets.load(), 0u);
  EXPECT_EQ(c.bytes.load(), 0u);
}

// ── Target ────────────────────────────────────────────────────────────────────

TEST(Target, DefaultKindIsAccept) {
  Target t;
  EXPECT_EQ(t.kind, Target::Kind::kAccept);
}

TEST(Target, DropKind) {
  Target t;
  t.kind = Target::Kind::kDrop;
  EXPECT_EQ(t.kind, Target::Kind::kDrop);
}

TEST(Target, RejectWithIcmpType) {
  Target t;
  t.kind = Target::Kind::kReject;
  t.reject_with = IcmpType{3, 1};
  EXPECT_EQ(t.kind, Target::Kind::kReject);
  EXPECT_EQ(t.reject_with.type, 3u);
  EXPECT_EQ(t.reject_with.code, 1u);
}

TEST(Target, LogWithPrefixAndLevel) {
  Target t;
  t.kind       = Target::Kind::kLog;
  t.log_prefix = "DROPPED: ";
  t.log_level  = 4;
  EXPECT_EQ(t.log_prefix, "DROPPED: ");
  EXPECT_EQ(t.log_level, 4u);
}

TEST(Target, JumpToChain) {
  Target t;
  t.kind       = Target::Kind::kJump;
  t.jump_chain = "MY_CHAIN";
  EXPECT_EQ(t.jump_chain, "MY_CHAIN");
}

TEST(Target, DnatWithAddress) {
  Target t;
  t.kind    = Target::Kind::kDnat;
  t.to_addr = "192.168.1.100:8080";
  EXPECT_EQ(t.to_addr, "192.168.1.100:8080");
}

// ── Chain policy ──────────────────────────────────────────────────────────────

TEST(Chain, DefaultPolicyIsNullopt) {
  Chain c;
  c.name = "INPUT";
  EXPECT_FALSE(c.policy.has_value());
}

TEST(Chain, PolicyCanBeSetToAccept) {
  Chain c;
  c.name   = "INPUT";
  c.policy = Target{Target::Kind::kAccept};
  ASSERT_TRUE(c.policy.has_value());
  EXPECT_EQ(c.policy->kind, Target::Kind::kAccept);
}

TEST(Chain, PolicyCanBeSetToDrop) {
  Chain c;
  c.name   = "FORWARD";
  c.policy = Target{Target::Kind::kDrop};
  ASSERT_TRUE(c.policy.has_value());
  EXPECT_EQ(c.policy->kind, Target::Kind::kDrop);
}

TEST(Chain, PolicyCanBeCleared) {
  Chain c;
  c.name   = "OUTPUT";
  c.policy = Target{Target::Kind::kAccept};
  c.policy.reset();
  EXPECT_FALSE(c.policy.has_value());
}

// ── MatchExtRegistry ──────────────────────────────────────────────────────────

TEST(MatchExtRegistry, ParseUnknownModuleThrows) {
  MatchExtRegistry reg;
  EXPECT_THROW(reg.Parse("nonexistent", {}), std::runtime_error);
}

TEST(MatchExtRegistry, ParseUnknownModuleThrowsWithModuleName) {
  MatchExtRegistry reg;
  try {
    reg.Parse("limit", {});
    FAIL() << "Expected std::runtime_error";
  } catch (const std::runtime_error& e) {
    EXPECT_NE(std::string(e.what()).find("limit"), std::string::npos);
  }
}

// ── MatchExtRegistry — builtin modules ───────────────────────────────────────

TEST(MatchExtRegistry, RegisterBuiltinModulesMultiportDports) {
  MatchExtRegistry reg;
  reg.RegisterBuiltinModules();
  // --dports 80,443 should successfully create MultiportMatch
  auto m = reg.Parse("multiport", {"--dports", "80,443"});
  ASSERT_NE(m, nullptr);
}

TEST(MatchExtRegistry, RegisterBuiltinModulesMultiportSports) {
  MatchExtRegistry reg;
  reg.RegisterBuiltinModules();
  auto m = reg.Parse("multiport", {"--sports", "1024:2048"});
  ASSERT_NE(m, nullptr);
}

TEST(MatchExtRegistry, RegisterBuiltinModulesMultiportNegated) {
  MatchExtRegistry reg;
  reg.RegisterBuiltinModules();
  auto m = reg.Parse("multiport", {"!", "--dports", "80"});
  ASSERT_NE(m, nullptr);
}

TEST(MatchExtRegistry, RegisterBuiltinModulesMultiportBadFlagThrows) {
  MatchExtRegistry reg;
  reg.RegisterBuiltinModules();
  EXPECT_THROW(reg.Parse("multiport", {"--ports", "80"}), std::invalid_argument);
}

TEST(MatchExtRegistry, RegisterBuiltinModulesMultiportMissingArgsThrows) {
  MatchExtRegistry reg;
  reg.RegisterBuiltinModules();
  EXPECT_THROW(reg.Parse("multiport", {"--dports"}), std::invalid_argument);
}

TEST(MatchExtRegistry, RegisterBuiltinModulesState) {
  MatchExtRegistry reg;
  reg.RegisterBuiltinModules();
  auto m = reg.Parse("state", {"--state", "NEW,ESTABLISHED"});
  ASSERT_NE(m, nullptr);
}

TEST(MatchExtRegistry, RegisterBuiltinModulesStateNegated) {
  MatchExtRegistry reg;
  reg.RegisterBuiltinModules();
  auto m = reg.Parse("state", {"!", "--state", "INVALID"});
  ASSERT_NE(m, nullptr);
}

TEST(MatchExtRegistry, RegisterBuiltinModulesStateBadFlagThrows) {
  MatchExtRegistry reg;
  reg.RegisterBuiltinModules();
  EXPECT_THROW(reg.Parse("state", {"--states", "NEW"}), std::invalid_argument);
}

TEST(MatchExtRegistry, RegisterBuiltinModulesStateMissingArgsThrows) {
  MatchExtRegistry reg;
  reg.RegisterBuiltinModules();
  EXPECT_THROW(reg.Parse("state", {"--state"}), std::invalid_argument);
}
