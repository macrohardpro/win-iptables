// Copyright (c) winiptables authors. All rights reserved.
// packet.cpp -- IPv4/IPv6 packet parsing implementation
//
// Does not depend on WinDivert headers, uses inline minimal packed structs,
// easy to compile in unit test environments.

#include "winiptables/packet.hpp"

#include <cstring>

// Protocol number constants
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif
#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

// IPv6 extension header next-header values
static constexpr uint8_t kIpv6ExtHopByHop = 0;
static constexpr uint8_t kIpv6ExtRouting  = 43;
static constexpr uint8_t kIpv6ExtFragment = 44;
static constexpr uint8_t kIpv6ExtDestOpt  = 60;
static constexpr uint8_t kIpv6ExtAuth     = 51;

// Minimal network header structs (does not depend on WinDivert)
#pragma pack(push, 1)

struct MinIpv4Hdr {
  uint8_t  ver_ihl;
  uint8_t  tos;
  uint16_t total_len;
  uint16_t id;
  uint16_t frag_off;
  uint8_t  ttl;
  uint8_t  protocol;
  uint16_t checksum;
  uint8_t  src_addr[4];
  uint8_t  dst_addr[4];
};

struct MinIpv6Hdr {
  uint32_t ver_tc_fl;
  uint16_t payload_len;
  uint8_t  next_hdr;
  uint8_t  hop_limit;
  uint8_t  src_addr[16];
  uint8_t  dst_addr[16];
};

struct MinTcpHdr {
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t seq;
  uint32_t ack;
  uint8_t  data_off;
  uint8_t  flags;
  uint16_t window;
  uint16_t checksum;
  uint16_t urg_ptr;
};

struct MinUdpHdr {
  uint16_t src_port;
  uint16_t dst_port;
  uint16_t length;
  uint16_t checksum;
};

struct MinIcmpHdr {
  uint8_t  type;
  uint8_t  code;
  uint16_t checksum;
};

#pragma pack(pop)

// Read uint16_t from network byte order
static inline uint16_t ReadBe16(const uint8_t* p) noexcept {
  return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

namespace winiptables {

std::optional<Packet> ParseIPv4(const uint8_t* data, std::size_t len) {
  if (!data || len < sizeof(MinIpv4Hdr)) return std::nullopt;

  const auto* ip = reinterpret_cast<const MinIpv4Hdr*>(data);

  const uint8_t version = (ip->ver_ihl >> 4) & 0x0F;
  if (version != 4) return std::nullopt;

  const uint8_t ihl = ip->ver_ihl & 0x0F;
  if (ihl < 5) return std::nullopt;

  const std::size_t ip_hdr_len = static_cast<std::size_t>(ihl) * 4;
  if (len < ip_hdr_len) return std::nullopt;

  Packet pkt;
  pkt.af       = AddressFamily::kIPv4;
  pkt.protocol = ip->protocol;
  pkt.src_ip   = IpAddress::FromV4(ip->src_addr);
  pkt.dst_ip   = IpAddress::FromV4(ip->dst_addr);
  pkt.raw_data.assign(data, data + len);

  const uint8_t*  transport     = data + ip_hdr_len;
  const std::size_t transport_len = len - ip_hdr_len;

  switch (ip->protocol) {
    case IPPROTO_TCP: {
      if (transport_len < sizeof(MinTcpHdr)) return std::nullopt;
      const auto* tcp = reinterpret_cast<const MinTcpHdr*>(transport);
      pkt.src_port  = ReadBe16(reinterpret_cast<const uint8_t*>(&tcp->src_port));
      pkt.dst_port  = ReadBe16(reinterpret_cast<const uint8_t*>(&tcp->dst_port));
      pkt.tcp_flags = tcp->flags;
      break;
    }
    case IPPROTO_UDP: {
      if (transport_len < sizeof(MinUdpHdr)) return std::nullopt;
      const auto* udp = reinterpret_cast<const MinUdpHdr*>(transport);
      pkt.src_port = ReadBe16(reinterpret_cast<const uint8_t*>(&udp->src_port));
      pkt.dst_port = ReadBe16(reinterpret_cast<const uint8_t*>(&udp->dst_port));
      break;
    }
    case IPPROTO_ICMP: {
      if (transport_len < sizeof(MinIcmpHdr)) return std::nullopt;
      const auto* icmp = reinterpret_cast<const MinIcmpHdr*>(transport);
      pkt.icmp_type = icmp->type;
      pkt.icmp_code = icmp->code;
      break;
    }
    default:
      break;
  }

  return pkt;
}

std::optional<Packet> ParseIPv6(const uint8_t* data, std::size_t len) {
  if (!data || len < sizeof(MinIpv6Hdr)) return std::nullopt;

  const auto* ip6 = reinterpret_cast<const MinIpv6Hdr*>(data);

  const uint8_t version = (data[0] >> 4) & 0x0F;
  if (version != 6) return std::nullopt;

  Packet pkt;
  pkt.af     = AddressFamily::kIPv6;
  pkt.src_ip = IpAddress::FromV6(ip6->src_addr);
  pkt.dst_ip = IpAddress::FromV6(ip6->dst_addr);
  pkt.raw_data.assign(data, data + len);

  // Skip extension headers, process up to 8
  uint8_t     next_hdr = ip6->next_hdr;
  std::size_t offset   = sizeof(MinIpv6Hdr);

  for (int i = 0; i < 8; ++i) {
    const bool is_ext = (next_hdr == kIpv6ExtHopByHop ||
                         next_hdr == kIpv6ExtRouting   ||
                         next_hdr == kIpv6ExtDestOpt   ||
                         next_hdr == kIpv6ExtAuth);
    const bool is_frag = (next_hdr == kIpv6ExtFragment);

    if (!is_ext && !is_frag) break;
    if (offset + 2 > len) return std::nullopt;

    if (is_frag) {
      next_hdr = data[offset];
      offset  += 8;
    } else {
      const uint8_t ext_len = data[offset + 1];
      next_hdr = data[offset];
      offset  += static_cast<std::size_t>(ext_len + 1) * 8;
    }

    if (offset > len) return std::nullopt;
  }

  pkt.protocol = next_hdr;
  const uint8_t*  transport     = data + offset;
  const std::size_t transport_len = (offset <= len) ? (len - offset) : 0;

  switch (next_hdr) {
    case IPPROTO_TCP: {
      if (transport_len < sizeof(MinTcpHdr)) return std::nullopt;
      const auto* tcp = reinterpret_cast<const MinTcpHdr*>(transport);
      pkt.src_port  = ReadBe16(reinterpret_cast<const uint8_t*>(&tcp->src_port));
      pkt.dst_port  = ReadBe16(reinterpret_cast<const uint8_t*>(&tcp->dst_port));
      pkt.tcp_flags = tcp->flags;
      break;
    }
    case IPPROTO_UDP: {
      if (transport_len < sizeof(MinUdpHdr)) return std::nullopt;
      const auto* udp = reinterpret_cast<const MinUdpHdr*>(transport);
      pkt.src_port = ReadBe16(reinterpret_cast<const uint8_t*>(&udp->src_port));
      pkt.dst_port = ReadBe16(reinterpret_cast<const uint8_t*>(&udp->dst_port));
      break;
    }
    case IPPROTO_ICMPV6: {
      if (transport_len < sizeof(MinIcmpHdr)) return std::nullopt;
      const auto* icmp = reinterpret_cast<const MinIcmpHdr*>(transport);
      pkt.icmp_type = icmp->type;
      pkt.icmp_code = icmp->code;
      break;
    }
    default:
      break;
  }

  return pkt;
}

}  // namespace winiptables