// Copyright (c) winiptables authors. All rights reserved.
// matches/tcp.hpp -- TCP/UDP/ICMP match conditions: --sport/--dport/--tcp-flags/--icmp-type

#ifndef WINIPTABLES_MATCHES_TCP_HPP_
#define WINIPTABLES_MATCHES_TCP_HPP_

#include "winiptables/imatch.hpp"
#include "winiptables/packet.hpp"

#include <cstdint>
#include <string>

namespace winiptables {

// TCP flag constants
namespace tcp_flags {
constexpr uint8_t kFin = 0x01;
constexpr uint8_t kSyn = 0x02;
constexpr uint8_t kRst = 0x04;
constexpr uint8_t kPsh = 0x08;
constexpr uint8_t kAck = 0x10;
constexpr uint8_t kUrg = 0x20;
}  // namespace tcp_flags

// Matches --sport <port> or --sport <min>:<max> (source port or range).
class SrcPortMatch final : public IMatch {
 public:
  SrcPortMatch(uint16_t port_min, uint16_t port_max, bool negated = false)
      : port_min_(port_min), port_max_(port_max), negated_(negated) {}

  [[nodiscard]] bool Matches(const Packet& packet,
                              const MatchContext& ctx) const override;
  [[nodiscard]] std::string ToRuleText() const override;

 private:
  uint16_t port_min_;
  uint16_t port_max_;
  bool     negated_;
};

// Matches --dport <port> or --dport <min>:<max> (destination port or range).
class DstPortMatch final : public IMatch {
 public:
  DstPortMatch(uint16_t port_min, uint16_t port_max, bool negated = false)
      : port_min_(port_min), port_max_(port_max), negated_(negated) {}

  [[nodiscard]] bool Matches(const Packet& packet,
                              const MatchContext& ctx) const override;
  [[nodiscard]] std::string ToRuleText() const override;

 private:
  uint16_t port_min_;
  uint16_t port_max_;
  bool     negated_;
};

// Matches --tcp-flags <mask> <comp>.
// Match condition: (packet.tcp_flags & mask) == comp.
class TcpFlagsMatch final : public IMatch {
 public:
  TcpFlagsMatch(uint8_t mask, uint8_t comp, bool negated = false)
      : mask_(mask), comp_(comp), negated_(negated) {}

  [[nodiscard]] bool Matches(const Packet& packet,
                              const MatchContext& ctx) const override;
  [[nodiscard]] std::string ToRuleText() const override;

  // Parses comma-separated flag name string (e.g. "SYN,ACK"), returns flag bitmask.
  static uint8_t ParseFlags(const std::string& flags_str);

 private:
  uint8_t mask_;
  uint8_t comp_;
  bool    negated_;
};

// Matches --icmp-type <type> (ICMP type).
class IcmpTypeMatch final : public IMatch {
 public:
  explicit IcmpTypeMatch(uint8_t icmp_type, bool negated = false)
      : icmp_type_(icmp_type), negated_(negated) {}

  [[nodiscard]] bool Matches(const Packet& packet,
                              const MatchContext& ctx) const override;
  [[nodiscard]] std::string ToRuleText() const override;

 private:
  uint8_t icmp_type_;
  bool    negated_;
};

}  // namespace winiptables

#endif  // WINIPTABLES_MATCHES_TCP_HPP_