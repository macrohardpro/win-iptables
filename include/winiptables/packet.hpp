// Copyright (c) winiptables authors. All rights reserved.
// packet.hpp -- IPv4/IPv6 packet structure and parsing function declarations

#ifndef WINIPTABLES_PACKET_HPP_
#define WINIPTABLES_PACKET_HPP_

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

namespace winiptables {

// Address family
enum class AddressFamily : uint8_t {
  kIPv4 = 4,
  kIPv6 = 6,
};

// IP address, IPv4 uses 4 bytes, IPv6 uses 16 bytes (both in network byte order).
struct IpAddress {
  AddressFamily af = AddressFamily::kIPv4;
  union {
    uint8_t v4[4];
    uint8_t v6[16];
  };

  static IpAddress FromV4(const uint8_t src[4]) noexcept {
    IpAddress a{};
    a.af = AddressFamily::kIPv4;
    a.v4[0] = src[0]; a.v4[1] = src[1];
    a.v4[2] = src[2]; a.v4[3] = src[3];
    return a;
  }

  static IpAddress FromV6(const uint8_t src[16]) noexcept {
    IpAddress a{};
    a.af = AddressFamily::kIPv6;
    for (int i = 0; i < 16; ++i) a.v6[i] = src[i];
    return a;
  }

  bool operator==(const IpAddress& other) const noexcept {
    if (af != other.af) return false;
    if (af == AddressFamily::kIPv4) {
      return v4[0] == other.v4[0] && v4[1] == other.v4[1] &&
             v4[2] == other.v4[2] && v4[3] == other.v4[3];
    }
    for (int i = 0; i < 16; ++i) {
      if (v6[i] != other.v6[i]) return false;
    }
    return true;
  }
};

// Packet direction
enum class Direction : uint8_t {
  kInbound  = 0,
  kOutbound = 1,
  kForward  = 2,
};

// Captured network packet, contains parsed header fields and raw bytes.
struct Packet {
  AddressFamily af       = AddressFamily::kIPv4;
  IpAddress     src_ip   = {};
  IpAddress     dst_ip   = {};
  uint8_t       protocol = 0;    // IPPROTO_TCP/UDP/ICMP etc.
  uint16_t      src_port = 0;    // TCP/UDP source port (host byte order)
  uint16_t      dst_port = 0;    // TCP/UDP destination port (host byte order)
  uint8_t       tcp_flags = 0;   // TCP flags
  uint8_t       icmp_type = 0;   // ICMP/ICMPv6 type
  uint8_t       icmp_code = 0;   // ICMP/ICMPv6 code
  uint32_t      iface_index = 0; // Network interface index
  Direction     direction = Direction::kInbound;
  std::vector<uint8_t> raw_data; // Raw packet bytes

  [[nodiscard]] std::size_t size() const noexcept { return raw_data.size(); }
  [[nodiscard]] bool IsIPv6() const noexcept {
    return af == AddressFamily::kIPv6;
  }
  [[nodiscard]] const std::vector<uint8_t>& ToBytes() const noexcept {
    return raw_data;
  }

  // Returns "a.b.c.d" for IPv4, or abbreviated hex for IPv6.
  [[nodiscard]] std::string SrcIpStr() const { return IpStr(src_ip); }
  [[nodiscard]] std::string DstIpStr() const { return IpStr(dst_ip); }

private:
  static std::string IpStr(const IpAddress& ip) {
    if (ip.af == AddressFamily::kIPv4) {
      return std::to_string(ip.v4[0]) + '.' + std::to_string(ip.v4[1]) + '.'
           + std::to_string(ip.v4[2]) + '.' + std::to_string(ip.v4[3]);
    }
    // IPv6: compact hex groups
    char buf[40] = {};
    int off = 0;
    for (int i = 0; i < 16; i += 2) {
      if (i) buf[off++] = ':';
      off += snprintf(buf + off, sizeof(buf) - off, "%x",
                      (ip.v6[i] << 8) | ip.v6[i + 1]);
    }
    return buf;
  }
};

// Parses IPv4 raw packet. Returns std::nullopt on insufficient data or format error.
[[nodiscard]] std::optional<Packet> ParseIPv4(const uint8_t* data,
                                               std::size_t len);

// Parses IPv6 raw packet. Returns std::nullopt on insufficient data or format error.
[[nodiscard]] std::optional<Packet> ParseIPv6(const uint8_t* data,
                                               std::size_t len);

}  // namespace winiptables

#endif  // WINIPTABLES_PACKET_HPP_