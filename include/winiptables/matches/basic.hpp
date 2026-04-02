// Copyright (c) winiptables authors. All rights reserved.
// matches/basic.hpp -- Basic match conditions: -p/-s/-d/-i/-o

#ifndef WINIPTABLES_MATCHES_BASIC_HPP_
#define WINIPTABLES_MATCHES_BASIC_HPP_

#include "winiptables/imatch.hpp"
#include "winiptables/packet.hpp"

#include <cstdint>
#include <string>
#include <utility>

namespace winiptables {

// CIDR parsing result
struct CidrResult {
  uint32_t network_be;  // Network address (network byte order)
  uint8_t  prefix_len;  // Prefix length (0-32)
};

// Parses CIDR string in "192.168.1.0/24" or "10.0.0.1" format.
// Throws std::invalid_argument on parse failure.
CidrResult ParseCidr(const std::string& cidr);

// Matches -p <protocol>. protocol=0 means all.
class ProtocolMatch final : public IMatch {
 public:
  explicit ProtocolMatch(uint8_t protocol, bool negated = false)
      : protocol_(protocol), negated_(negated) {}

  [[nodiscard]] bool Matches(const Packet& packet,
                              const MatchContext& ctx) const override;
  [[nodiscard]] std::string ToRuleText() const override;

 private:
  uint8_t protocol_;
  bool    negated_;
};

// Matches -s <ip/cidr> (source IP address or subnet).
class SrcIpMatch final : public IMatch {
 public:
  SrcIpMatch(uint32_t network_be, uint8_t prefix_len, bool negated = false)
      : network_(network_be), prefix_len_(prefix_len), negated_(negated) {}

  [[nodiscard]] bool Matches(const Packet& packet,
                              const MatchContext& ctx) const override;
  [[nodiscard]] std::string ToRuleText() const override;

 private:
  uint32_t network_;
  uint8_t  prefix_len_;
  bool     negated_;
};

// Matches -d <ip/cidr> (destination IP address or subnet).
class DstIpMatch final : public IMatch {
 public:
  DstIpMatch(uint32_t network_be, uint8_t prefix_len, bool negated = false)
      : network_(network_be), prefix_len_(prefix_len), negated_(negated) {}

  [[nodiscard]] bool Matches(const Packet& packet,
                              const MatchContext& ctx) const override;
  [[nodiscard]] std::string ToRuleText() const override;

 private:
  uint32_t network_;
  uint8_t  prefix_len_;
  bool     negated_;
};

// Matches -i <iface> (inbound network interface index).
class InIfaceMatch final : public IMatch {
 public:
  explicit InIfaceMatch(uint32_t iface_index, bool negated = false)
      : iface_index_(iface_index), negated_(negated) {}

  [[nodiscard]] bool Matches(const Packet& packet,
                              const MatchContext& ctx) const override;
  [[nodiscard]] std::string ToRuleText() const override;

 private:
  uint32_t iface_index_;
  bool     negated_;
};

// Matches -o <iface> (outbound network interface index).
class OutIfaceMatch final : public IMatch {
 public:
  explicit OutIfaceMatch(uint32_t iface_index, bool negated = false)
      : iface_index_(iface_index), negated_(negated) {}

  [[nodiscard]] bool Matches(const Packet& packet,
                              const MatchContext& ctx) const override;
  [[nodiscard]] std::string ToRuleText() const override;

 private:
  uint32_t iface_index_;
  bool     negated_;
};

}  // namespace winiptables

#endif  // WINIPTABLES_MATCHES_BASIC_HPP_