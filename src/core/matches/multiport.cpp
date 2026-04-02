// Copyright (c) winiptables authors. All rights reserved.
// multiport.cpp -- multiport extension module implementation (Task 5.1)

#include "winiptables/matches/multiport.hpp"

#include <sstream>
#include <stdexcept>
#include <string>

namespace winiptables {

// -- Helper --------------------------------------------------------------------

static bool IsTcpOrUdp(uint8_t protocol) {
  return protocol == 6 || protocol == 17;
}

// Parses single token: "80" or "1024:2048"
static PortRange ParseToken(const std::string& token) {
  const auto colon = token.find(':');
  if (colon == std::string::npos) {
    // Single port
    const int port = std::stoi(token);
    if (port < 0 || port > 65535)
      throw std::invalid_argument("Port out of range: " + token);
    return {static_cast<uint16_t>(port), static_cast<uint16_t>(port)};
  }
  // Range min:max
  const int lo = std::stoi(token.substr(0, colon));
  const int hi = std::stoi(token.substr(colon + 1));
  if (lo < 0 || lo > 65535 || hi < 0 || hi > 65535)
    throw std::invalid_argument("Port out of range in: " + token);
  if (lo > hi)
    throw std::invalid_argument("Port range min > max: " + token);
  return {static_cast<uint16_t>(lo), static_cast<uint16_t>(hi)};
}

// -- MultiportMatch::Parse -----------------------------------------------------

// static
std::unique_ptr<MultiportMatch> MultiportMatch::Parse(
    const std::string& ports_str, bool is_src, bool negated) {
  std::vector<PortRange> ranges;
  std::istringstream ss(ports_str);
  std::string token;
  while (std::getline(ss, token, ',')) {
    // Trim leading and trailing spaces
    while (!token.empty() && token.front() == ' ') token.erase(token.begin());
    while (!token.empty() && token.back()  == ' ') token.pop_back();
    if (token.empty()) continue;
    ranges.push_back(ParseToken(token));
  }
  if (ranges.empty())
    throw std::invalid_argument("Empty port list");
  return std::make_unique<MultiportMatch>(std::move(ranges), is_src, negated);
}

// -- MultiportMatch::Matches --------------------------------------------------

bool MultiportMatch::Matches(const Packet& packet,
                              const MatchContext& /*ctx*/) const {
  if (!IsTcpOrUdp(packet.protocol)) return negated_;
  const uint16_t port = is_src_ ? packet.src_port : packet.dst_port;
  bool hit = false;
  for (const auto& r : ranges_) {
    if (port >= r.min && port <= r.max) {
      hit = true;
      break;
    }
  }
  return negated_ ? !hit : hit;
}

// -- MultiportMatch::ToRuleText -----------------------------------------------

std::string MultiportMatch::ToRuleText() const {
  std::string result;
  if (negated_) result += "! ";
  result += "-m multiport ";
  result += is_src_ ? "--sports " : "--dports ";
  bool first = true;
  for (const auto& r : ranges_) {
    if (!first) result += ",";
    if (r.min == r.max) {
      result += std::to_string(r.min);
    } else {
      result += std::to_string(r.min) + ":" + std::to_string(r.max);
    }
    first = false;
  }
  return result;
}

}  // namespace winiptables