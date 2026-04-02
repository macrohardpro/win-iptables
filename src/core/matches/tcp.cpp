// Copyright (c) winiptables authors. All rights reserved.
// matches/tcp.cpp -- TCP/UDP/ICMP match conditions implementation

#include "winiptables/matches/tcp.hpp"

#include <sstream>
#include <stdexcept>

namespace winiptables {

// -- Helper --------------------------------------------------------------------

static bool PortInRange(uint16_t port, uint16_t min_port, uint16_t max_port) {
  return port >= min_port && port <= max_port;
}

static bool IsTcpOrUdp(uint8_t protocol) {
  return protocol == 6 || protocol == 17;
}

// Converts flag bitmask to comma-separated name string
static std::string FlagsToStr(uint8_t flags) {
  if (flags == 0) return "NONE";
  std::string s;
  if (flags & tcp_flags::kSyn) { if (!s.empty()) s += ','; s += "SYN"; }
  if (flags & tcp_flags::kAck) { if (!s.empty()) s += ','; s += "ACK"; }
  if (flags & tcp_flags::kFin) { if (!s.empty()) s += ','; s += "FIN"; }
  if (flags & tcp_flags::kRst) { if (!s.empty()) s += ','; s += "RST"; }
  if (flags & tcp_flags::kPsh) { if (!s.empty()) s += ','; s += "PSH"; }
  if (flags & tcp_flags::kUrg) { if (!s.empty()) s += ','; s += "URG"; }
  return s;
}

// -- SrcPortMatch --------------------------------------------------------------

bool SrcPortMatch::Matches(const Packet& packet,
                            const MatchContext& /*ctx*/) const {
  if (!IsTcpOrUdp(packet.protocol)) return negated_;
  const bool result = PortInRange(packet.src_port, port_min_, port_max_);
  return negated_ ? !result : result;
}

std::string SrcPortMatch::ToRuleText() const {
  const std::string range = (port_min_ == port_max_)
      ? std::to_string(port_min_)
      : std::to_string(port_min_) + ":" + std::to_string(port_max_);
  return std::string(negated_ ? "! " : "") + "--sport " + range;
}

// -- DstPortMatch --------------------------------------------------------------

bool DstPortMatch::Matches(const Packet& packet,
                            const MatchContext& /*ctx*/) const {
  if (!IsTcpOrUdp(packet.protocol)) return negated_;
  const bool result = PortInRange(packet.dst_port, port_min_, port_max_);
  return negated_ ? !result : result;
}

std::string DstPortMatch::ToRuleText() const {
  const std::string range = (port_min_ == port_max_)
      ? std::to_string(port_min_)
      : std::to_string(port_min_) + ":" + std::to_string(port_max_);
  return std::string(negated_ ? "! " : "") + "--dport " + range;
}

// -- TcpFlagsMatch -------------------------------------------------------------

// static
uint8_t TcpFlagsMatch::ParseFlags(const std::string& flags_str) {
  uint8_t result = 0;
  std::istringstream ss(flags_str);
  std::string token;
  while (std::getline(ss, token, ',')) {
    // Trim leading and trailing spaces
    while (!token.empty() && token.front() == ' ') token.erase(token.begin());
    while (!token.empty() && token.back()  == ' ') token.pop_back();

    if      (token == "SYN")  result |= tcp_flags::kSyn;
    else if (token == "ACK")  result |= tcp_flags::kAck;
    else if (token == "FIN")  result |= tcp_flags::kFin;
    else if (token == "RST")  result |= tcp_flags::kRst;
    else if (token == "PSH")  result |= tcp_flags::kPsh;
    else if (token == "URG")  result |= tcp_flags::kUrg;
    else if (token == "NONE") { /* 0 */ }
    else if (token == "ALL")  result |= 0x3Fu;
    else throw std::invalid_argument("Unknown TCP flag: " + token);
  }
  return result;
}

bool TcpFlagsMatch::Matches(const Packet& packet,
                             const MatchContext& /*ctx*/) const {
  if (packet.protocol != 6) return negated_;
  const bool result = (packet.tcp_flags & mask_) == comp_;
  return negated_ ? !result : result;
}

std::string TcpFlagsMatch::ToRuleText() const {
  return std::string(negated_ ? "! " : "") +
         "--tcp-flags " + FlagsToStr(mask_) + " " + FlagsToStr(comp_);
}

// -- IcmpTypeMatch -------------------------------------------------------------

bool IcmpTypeMatch::Matches(const Packet& packet,
                              const MatchContext& /*ctx*/) const {
  const bool is_icmp = (packet.protocol == 1 || packet.protocol == 58);
  if (!is_icmp) return negated_;
  const bool result = (packet.icmp_type == icmp_type_);
  return negated_ ? !result : result;
}

std::string IcmpTypeMatch::ToRuleText() const {
  return std::string(negated_ ? "! " : "") +
         "--icmp-type " + std::to_string(icmp_type_);
}

}  // namespace winiptables