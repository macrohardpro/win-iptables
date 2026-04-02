// Copyright (c) winiptables authors. All rights reserved.
// matches/basic.cpp -- Basic match conditions implementation: -p/-s/-d/-i/-o

#include "winiptables/matches/basic.hpp"

#include <stdexcept>
#include <cstring>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

namespace winiptables {

// -- Helper functions ----------------------------------------------------------

// Extract uint32_t from IpAddress (network byte order)
static uint32_t IpToU32(const IpAddress& ip) {
  uint32_t v = 0;
  std::memcpy(&v, ip.v4, 4);
  return v;
}

// Check if addr_be belongs to network_be/prefix_len subnet
static bool CidrContains(uint32_t addr_be, uint32_t network_be,
                          uint8_t prefix_len) {
  if (prefix_len == 0) return true;
  const uint32_t mask_h  = ~((1u << (32u - prefix_len)) - 1u);
  const uint32_t mask_be = htonl(mask_h);
  return (addr_be & mask_be) == network_be;
}

// -- ParseCidr ----------------------------------------------------------------

CidrResult ParseCidr(const std::string& cidr) {
  const auto slash = cidr.find('/');
  const std::string ip_str =
      (slash == std::string::npos) ? cidr : cidr.substr(0, slash);

  uint8_t prefix_len = 32;
  if (slash != std::string::npos) {
    const int pl = std::stoi(cidr.substr(slash + 1));
    if (pl < 0 || pl > 32) {
      throw std::invalid_argument("Invalid prefix length: " + cidr);
    }
    prefix_len = static_cast<uint8_t>(pl);
  }

  struct sockaddr_in sa;
  if (InetPton(AF_INET, ip_str.c_str(), &sa.sin_addr) != 1) {
    throw std::invalid_argument("Invalid IPv4 address: " + ip_str);
  }

  CidrResult r;
  r.network_be  = static_cast<uint32_t>(sa.sin_addr.s_addr);
  r.prefix_len   = prefix_len;
  return r;
}

// -- ProtocolMatch ------------------------------------------------------------

bool ProtocolMatch::Matches(const Packet& packet,
                              const MatchContext& /*ctx*/) const {
  const bool result = (protocol_ == 0) || (packet.protocol == protocol_);
  return negated_ ? !result : result;
}

std::string ProtocolMatch::ToRuleText() const {
  std::string proto;
  if (protocol_ == 0)  proto = "all";
  else if (protocol_ == 6)  proto = "tcp";
  else if (protocol_ == 17) proto = "udp";
  else if (protocol_ == 1)  proto = "icmp";
  else proto = std::to_string(protocol_);
  return std::string(negated_ ? "! " : "") + "-p " + proto;
}

// -- SrcIpMatch ----------------------------------------------------------------

bool SrcIpMatch::Matches(const Packet& packet,
                           const MatchContext& /*ctx*/) const {
  const uint32_t pkt_ip = IpToU32(packet.src_ip);
  const bool result = CidrContains(pkt_ip, network_, prefix_len_);
  return negated_ ? !result : result;
}

std::string SrcIpMatch::ToRuleText() const {
  struct in_addr ia;
  ia.s_addr = network_;
  char buf[INET_ADDRSTRLEN];
  InetNtop(AF_INET, &ia, buf, sizeof(buf));
  std::string ip = buf;
  if (prefix_len_ < 32) ip += "/" + std::to_string(prefix_len_);
  return std::string(negated_ ? "! " : "") + "-s " + ip;
}

// -- DstIpMatch ----------------------------------------------------------------

bool DstIpMatch::Matches(const Packet& packet,
                           const MatchContext& /*ctx*/) const {
  const uint32_t pkt_ip = IpToU32(packet.dst_ip);
  const bool result = CidrContains(pkt_ip, network_, prefix_len_);
  return negated_ ? !result : result;
}

std::string DstIpMatch::ToRuleText() const {
  struct in_addr ia;
  ia.s_addr = network_;
  char buf[INET_ADDRSTRLEN];
  InetNtop(AF_INET, &ia, buf, sizeof(buf));
  std::string ip = buf;
  if (prefix_len_ < 32) ip += "/" + std::to_string(prefix_len_);
  return std::string(negated_ ? "! " : "") + "-d " + ip;
}

// -- InIfaceMatch --------------------------------------------------------------

bool InIfaceMatch::Matches(const Packet& packet,
                             const MatchContext& /*ctx*/) const {
  const bool result = (packet.direction == Direction::kInbound ||
                       packet.direction == Direction::kForward) &&
                      (packet.iface_index == iface_index_);
  return negated_ ? !result : result;
}

std::string InIfaceMatch::ToRuleText() const {
  return std::string(negated_ ? "! " : "") + "-i " + std::to_string(iface_index_);
}

// -- OutIfaceMatch -------------------------------------------------------------

bool OutIfaceMatch::Matches(const Packet& packet,
                              const MatchContext& /*ctx*/) const {
  const bool result = (packet.direction == Direction::kOutbound ||
                       packet.direction == Direction::kForward) &&
                      (packet.iface_index == iface_index_);
  return negated_ ? !result : result;
}

std::string OutIfaceMatch::ToRuleText() const {
  return std::string(negated_ ? "! " : "") + "-o " + std::to_string(iface_index_);
}

}  // namespace winiptables