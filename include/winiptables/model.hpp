// Copyright (c) winiptables authors. All rights reserved.
// model.hpp -- Core data models: TableKind, Chain, Rule, Target, etc

#ifndef WINIPTABLES_MODEL_HPP_
#define WINIPTABLES_MODEL_HPP_

#include <atomic>
#include <cstdint>
#include <list>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace winiptables {

// Forward declarations
class IMatch;

// Table types. Raw is reserved, not implemented in current version.
enum class TableKind {
  kRaw    = 0,
  kMangle = 1,
  kNat    = 2,
  kFilter = 3,
};

// Built-in chain types
enum class BuiltinChain {
  kInput,
  kOutput,
  kForward,
  kPrerouting,
  kPostrouting,
};

// ICMP type/code (for REJECT target)
struct IcmpType {
  uint8_t type = 0;
  uint8_t code = 0;
};

// Rule target actions
struct Target {
  enum class Kind {
    kAccept,
    kDrop,
    kReject,
    kReturn,
    kLog,
    kJump,
    kMasquerade,
    kDnat,
    kSnat,
  };

  Kind        kind       = Kind::kAccept;
  IcmpType    reject_with;           // Used for REJECT
  std::string log_prefix;            // Used for LOG
  uint8_t     log_level  = 0;        // Used for LOG
  std::string jump_chain;             // Used for JUMP
  std::string to_addr;                // Used for DNAT/SNAT, format "ip:port"
};

// Rule match counters (atomic operations, thread-safe).
// Uses std::atomic to ensure lock-free concurrent updates.
struct RuleCounters {
  mutable std::atomic<uint64_t> packets{0};
  mutable std::atomic<uint64_t> bytes{0};

  // Record one match, pkt_size is packet byte count.
  void Increment(uint64_t pkt_size) const {
    packets.fetch_add(1, std::memory_order_relaxed);
    bytes.fetch_add(pkt_size, std::memory_order_relaxed);
  }

  // Reset counters to zero
  void Reset() {
    packets.store(0, std::memory_order_relaxed);
    bytes.store(0, std::memory_order_relaxed);
  }

  // Non-copyable (atomic cannot be copied)
  RuleCounters() = default;
  RuleCounters(const RuleCounters&) = delete;
  RuleCounters& operator=(const RuleCounters&) = delete;
  // Explicit move constructor (atomic cannot be moved, manually implemented)
  RuleCounters(RuleCounters&& other) noexcept
      : packets(other.packets.load(std::memory_order_relaxed)),
        bytes(other.bytes.load(std::memory_order_relaxed)) {}
  RuleCounters& operator=(RuleCounters&&) = delete;
};

// A firewall rule: match condition list + target action + counter.
struct Rule {
  std::vector<std::unique_ptr<IMatch>> matches;  // Match conditions (smart pointers)
  Target                               target;
  RuleCounters                         counters;

  // Non-copyable (RuleCounters is non-copyable)
  Rule() = default;
  Rule(const Rule&) = delete;
  Rule& operator=(const Rule&) = delete;
  Rule(Rule&&) = default;
  Rule& operator=(Rule&&) = default;
};

// Rule chain: built-in chains have default policies, user-defined chains do not.
struct Chain {
  std::string                          name;
  std::optional<Target>                policy;  // Only built-in chains have default policy
  std::list<std::unique_ptr<Rule>>     rules;   // unique_ptr avoids Rule copy issues
};

// Rule table: contains several named chains.
struct Table {
  TableKind                              kind = TableKind::kFilter;
  std::unordered_map<std::string, Chain> chains;
};

}  // namespace winiptables

#endif  // WINIPTABLES_MODEL_HPP_