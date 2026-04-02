// Copyright (c) winiptables authors. All rights reserved.
// matches/state.cpp -- state extension module implementation (Task 5.2)
//
// Implements -m state --state NEW/ESTABLISHED/RELATED/INVALID matching.
// When StatefulTracker (Task 9) is not yet implemented, MatchContext has no tracker,
// so all packets are treated as NEW state.

#include "winiptables/matches/state.hpp"

#include <sstream>
#include <stdexcept>
#include <string>

namespace winiptables {

// -- Helper: convert state bitmask to comma-separated name string ---------------

static std::string StateMaskToStr(uint8_t mask) {
  std::string s;
  auto append = [&](const char* name) {
    if (!s.empty()) s += ',';
    s += name;
  };
  if (mask & conn_state::kNew)         append("NEW");
  if (mask & conn_state::kEstablished) append("ESTABLISHED");
  if (mask & conn_state::kRelated)     append("RELATED");
  if (mask & conn_state::kInvalid)     append("INVALID");
  return s;
}

// -- StateMatch::Parse ---------------------------------------------------------

// static
std::unique_ptr<StateMatch> StateMatch::Parse(const std::string& states_str,
                                               bool negated) {
  uint8_t mask = 0;
  std::istringstream ss(states_str);
  std::string token;
  while (std::getline(ss, token, ',')) {
    // Trim leading and trailing spaces
    while (!token.empty() && token.front() == ' ') token.erase(token.begin());
    while (!token.empty() && token.back()  == ' ') token.pop_back();
    if (token.empty()) continue;

    if      (token == "NEW")         mask |= conn_state::kNew;
    else if (token == "ESTABLISHED") mask |= conn_state::kEstablished;
    else if (token == "RELATED")     mask |= conn_state::kRelated;
    else if (token == "INVALID")     mask |= conn_state::kInvalid;
    else throw std::invalid_argument("Unknown connection state: " + token);
  }
  if (mask == 0)
    throw std::invalid_argument("Empty state list");
  return std::make_unique<StateMatch>(mask, negated);
}

// -- StateMatch::Matches -------------------------------------------------------

bool StateMatch::Matches(const Packet& /*packet*/,
                          const MatchContext& /*ctx*/) const {
  // StatefulTracker is not yet implemented (Task 9).
  // MatchContext is currently an empty struct, cannot query connection state.
  // Fallback strategy: treat all packets as NEW state.
  const uint8_t current_state = conn_state::kNew;
  const bool result = (current_state & state_mask_) != 0;
  return negated_ ? !result : result;
}

// -- StateMatch::ToRuleText ----------------------------------------------------

std::string StateMatch::ToRuleText() const {
  std::string result;
  if (negated_) result += "! ";
  result += "-m state --state ";
  result += StateMaskToStr(state_mask_);
  return result;
}

}  // namespace winiptables