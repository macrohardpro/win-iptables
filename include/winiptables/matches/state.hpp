// Copyright (c) winiptables authors. All rights reserved.
// matches/state.hpp -- state extension: -m state --state NEW/ESTABLISHED/RELATED/INVALID

#ifndef WINIPTABLES_MATCHES_STATE_HPP_
#define WINIPTABLES_MATCHES_STATE_HPP_

#include "winiptables/imatch.hpp"
#include "winiptables/packet.hpp"

#include <cstdint>
#include <memory>
#include <string>

namespace winiptables {

// Connection tracking state bitmask (corresponds to ConnState in StatefulTracker)
namespace conn_state {
constexpr uint8_t kNew         = 0x01;
constexpr uint8_t kEstablished = 0x02;
constexpr uint8_t kRelated     = 0x04;
constexpr uint8_t kInvalid     = 0x08;
}  // namespace conn_state

// Matches -m state --state <states>
// states is a combination of conn_state bitmask (e.g. kNew | kEstablished).
// If StatefulTracker is not present in MatchContext (Task 9 not implemented),
// all packets are treated as NEW state.
class StateMatch final : public IMatch {
 public:
  // state_mask: conn_state bitmask; negated: negation
  explicit StateMatch(uint8_t state_mask, bool negated = false)
      : state_mask_(state_mask), negated_(negated) {}

  [[nodiscard]] bool Matches(const Packet& packet,
                              const MatchContext& ctx) const override;
  [[nodiscard]] std::string ToRuleText() const override;

  // Parses "NEW,ESTABLISHED" format state string, returns StateMatch instance.
  // Throws std::invalid_argument on parse failure.
  static std::unique_ptr<StateMatch> Parse(const std::string& states_str,
                                           bool negated = false);

 private:
  uint8_t state_mask_;
  bool    negated_;
};

}  // namespace winiptables

#endif  // WINIPTABLES_MATCHES_STATE_HPP_