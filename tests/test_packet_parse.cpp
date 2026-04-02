// Copyright (c) winiptables authors. All rights reserved.
// test_packet_parse.cpp -- Packet parsing property tests
//
// Verifies Property 5 (IPv4/IPv6 classification invariant):
//   forall raw_packet: parse(raw_packet).IsIPv6() == raw_packet.is_ipv6_header()

#include <gtest/gtest.h>

#include "winiptables/packet.hpp"

#include <cstring>
#include <vector>

using namespace winiptables;

// -- Helper: construct minimal valid IPv4+TCP packet ----------------------------

static std::vector<uint8_t> MakeIPv4Tcp(const uint8_t src_ip[4],
                                         const uint8_t dst_ip[4],
                                         uint16_t src_port,
                                         uint16_t dst_port,
                                         uint8_t tcp_flags = 0x02) {
  std::vector<uint8_t> buf(40, 0);
  buf[0]  = 0x45;  // version=4, IHL=5
  buf[9]  = 6;     // TCP
  buf[12] = src_ip[0]; buf[13] = src_ip[1];
  buf[14] = src_ip[2]; buf[15] = src_ip[3];
  buf[16] = dst_ip[0]; buf[17] = dst_ip[1];
  buf[18] = dst_ip[2]; buf[19] = dst_ip[3];
  buf[20] = static_cast<uint8_t>(src_port >> 8);
  buf[21] = static_cast<uint8_t>(src_port & 0xFF);
  buf[22] = static_cast<uint8_t>(dst_port >> 8);
  buf[23] = static_cast<uint8_t>(dst_port & 0xFF);
  buf[32] = 0x50;  // data offset=5
  buf[33] = tcp_flags;
  return buf;
}

static std::vector<uint8_t> MakeIPv4Udp(const uint8_t src_ip[4],
                                          const uint8_t dst_ip[4],
                                          uint16_t src_port,
                                          uint16_t dst_port) {
  std::vector<uint8_t> buf(28, 0);
  buf[0]  = 0x45;
  buf[9]  = 17;  // UDP
  buf[12] = src_ip[0]; buf[13] = src_ip[1];
  buf[14] = src_ip[2]; buf[15] = src_ip[3];
  buf[16] = dst_ip[0]; buf[17] = dst_ip[1];
  buf[18] = dst_ip[2]; buf[19] = dst_ip[3];
  buf[20] = static_cast<uint8_t>(src_port >> 8);
  buf[21] = static_cast<uint8_t>(src_port & 0xFF);
  buf[22] = static_cast<uint8_t>(dst_port >> 8);
  buf[23] = static_cast<uint8_t>(dst_port & 0xFF);
  buf[24] = 0; buf[25] = 8;
  return buf;
}

static std::vector<uint8_t> MakeIPv6Tcp(const uint8_t src_ip[16],
                                          const uint8_t dst_ip[16],
                                          uint16_t src_port,
                                          uint16_t dst_port,
                                          uint8_t tcp_flags = 0x02) {
  std::vector<uint8_t> buf(60, 0);
  buf[0]  = 0x60;  // version=6
  buf[6]  = 6;     // next header=TCP
  buf[7]  = 64;    // hop limit
  std::memcpy(&buf[8],  src_ip, 16);
  std::memcpy(&buf[24], dst_ip, 16);
  buf[40] = static_cast<uint8_t>(src_port >> 8);
  buf[41] = static_cast<uint8_t>(src_port & 0xFF);
  buf[42] = static_cast<uint8_t>(dst_port >> 8);
  buf[43] = static_cast<uint8_t>(dst_port & 0xFF);
  buf[52] = 0x50;
  buf[53] = tcp_flags;
  return buf;
}

// -- IPv4 TCP parsing ----------------------------------------------------------

TEST(PacketParseTest, IPv4TcpParsed) {
  const uint8_t src[4] = {192, 168, 1, 1};
  const uint8_t dst[4] = {10,  0,   0, 1};
  auto buf = MakeIPv4Tcp(src, dst, 12345, 80, 0x02);

  auto result = ParseIPv4(buf.data(), buf.size());
  ASSERT_TRUE(result.has_value());

  EXPECT_EQ(result->af, AddressFamily::kIPv4);
  EXPECT_FALSE(result->IsIPv6());
  EXPECT_EQ(result->protocol, 6u);
  EXPECT_EQ(result->src_port, 12345u);
  EXPECT_EQ(result->dst_port, 80u);
  EXPECT_EQ(result->tcp_flags, 0x02u);
  EXPECT_EQ(result->size(), buf.size());
  EXPECT_EQ(result->src_ip.v4[0], 192u);
  EXPECT_EQ(result->dst_ip.v4[0], 10u);
}

// -- IPv4 UDP parsing ----------------------------------------------------------

TEST(PacketParseTest, IPv4UdpParsed) {
  const uint8_t src[4] = {172, 16, 0, 1};
  const uint8_t dst[4] = {8,   8,  8, 8};
  auto buf = MakeIPv4Udp(src, dst, 54321, 53);

  auto result = ParseIPv4(buf.data(), buf.size());
  ASSERT_TRUE(result.has_value());

  EXPECT_EQ(result->af, AddressFamily::kIPv4);
  EXPECT_FALSE(result->IsIPv6());
  EXPECT_EQ(result->protocol, 17u);
  EXPECT_EQ(result->src_port, 54321u);
  EXPECT_EQ(result->dst_port, 53u);
}

// -- IPv6 TCP parsing ----------------------------------------------------------

TEST(PacketParseTest, IPv6TcpParsed) {
  const uint8_t src[16] = {0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1};
  const uint8_t dst[16] = {0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,2};
  auto buf = MakeIPv6Tcp(src, dst, 9999, 443, 0x12);

  auto result = ParseIPv6(buf.data(), buf.size());
  ASSERT_TRUE(result.has_value());

  EXPECT_EQ(result->af, AddressFamily::kIPv6);
  EXPECT_TRUE(result->IsIPv6());
  EXPECT_EQ(result->protocol, 6u);
  EXPECT_EQ(result->src_port, 9999u);
  EXPECT_EQ(result->dst_port, 443u);
  EXPECT_EQ(result->tcp_flags, 0x12u);
}

// -- Property 5: IPv4/IPv6 classification invariant ----------------------------

TEST(PacketParseTest, Property5_IPv4ClassificationInvariant) {
  struct Case { uint8_t src[4]; uint8_t dst[4]; uint16_t sp; uint16_t dp; };
  const Case cases[] = {
    {{1,2,3,4},     {5,6,7,8},     1024, 80},
    {{10,0,0,1},    {10,0,0,2},    2048, 443},
    {{192,168,0,1}, {192,168,0,2}, 3000, 22},
  };
  for (const auto& c : cases) {
    auto buf = MakeIPv4Tcp(c.src, c.dst, c.sp, c.dp);
    auto result = ParseIPv4(buf.data(), buf.size());
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->IsIPv6()) << "IPv4 packet misclassified as IPv6";
  }
}

TEST(PacketParseTest, Property5_IPv6ClassificationInvariant) {
  const uint8_t src[16] = {0xfe,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
  const uint8_t dst[16] = {0xfe,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,2};
  const uint16_t ports[][2] = {{1024,80},{2048,443},{3000,22}};
  for (const auto& p : ports) {
    auto buf = MakeIPv6Tcp(src, dst, p[0], p[1]);
    auto result = ParseIPv6(buf.data(), buf.size());
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->IsIPv6()) << "IPv6 packet misclassified as IPv4";
  }
}

TEST(PacketParseTest, Property5_CrossParserRejectsWrongVersion) {
  const uint8_t src4[4] = {1,2,3,4};
  const uint8_t dst4[4] = {5,6,7,8};
  auto v4buf = MakeIPv4Tcp(src4, dst4, 1234, 80);
  EXPECT_FALSE(ParseIPv6(v4buf.data(), v4buf.size()).has_value());

  const uint8_t src6[16] = {0x20,0x01,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
  const uint8_t dst6[16] = {0x20,0x01,0,0,0,0,0,0,0,0,0,0,0,0,0,2};
  auto v6buf = MakeIPv6Tcp(src6, dst6, 1234, 80);
  EXPECT_FALSE(ParseIPv4(v6buf.data(), v6buf.size()).has_value());
}

// -- Returns nullopt when data is insufficient ---------------------------------

TEST(PacketParseTest, TooShortIPv4ReturnsNullopt) {
  EXPECT_FALSE(ParseIPv4(nullptr, 0).has_value());
  std::vector<uint8_t> short_buf(10, 0x45);
  EXPECT_FALSE(ParseIPv4(short_buf.data(), short_buf.size()).has_value());
}

TEST(PacketParseTest, TooShortIPv6ReturnsNullopt) {
  EXPECT_FALSE(ParseIPv6(nullptr, 0).has_value());
  std::vector<uint8_t> short_buf(20, 0);
  short_buf[0] = 0x60;
  EXPECT_FALSE(ParseIPv6(short_buf.data(), short_buf.size()).has_value());
}

TEST(PacketParseTest, IPv4TcpTooShortTransportReturnsNullopt) {
  std::vector<uint8_t> buf(30, 0);
  buf[0] = 0x45;
  buf[9] = 6;
  EXPECT_FALSE(ParseIPv4(buf.data(), buf.size()).has_value());
}

// -- ToBytes() and IsIPv6()/size() ---------------------------------------------

TEST(PacketParseTest, ToBytesReturnsRawData) {
  const uint8_t src[4] = {1,2,3,4};
  const uint8_t dst[4] = {5,6,7,8};
  auto buf = MakeIPv4Tcp(src, dst, 1111, 2222);

  auto result = ParseIPv4(buf.data(), buf.size());
  ASSERT_TRUE(result.has_value());

  const auto& bytes = result->ToBytes();
  EXPECT_EQ(bytes.size(), buf.size());
  EXPECT_EQ(bytes, buf);
  EXPECT_EQ(&bytes, &result->raw_data);
}

TEST(PacketParseTest, IsIPv6AndSizeMethods) {
  const uint8_t src4[4] = {1,2,3,4};
  const uint8_t dst4[4] = {5,6,7,8};
  auto v4buf = MakeIPv4Tcp(src4, dst4, 100, 200);
  auto v4pkt = ParseIPv4(v4buf.data(), v4buf.size());
  ASSERT_TRUE(v4pkt.has_value());
  EXPECT_FALSE(v4pkt->IsIPv6());
  EXPECT_EQ(v4pkt->size(), v4buf.size());

  const uint8_t src6[16] = {0x20,0x01,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
  const uint8_t dst6[16] = {0x20,0x01,0,0,0,0,0,0,0,0,0,0,0,0,0,2};
  auto v6buf = MakeIPv6Tcp(src6, dst6, 100, 200);
  auto v6pkt = ParseIPv6(v6buf.data(), v6buf.size());
  ASSERT_TRUE(v6pkt.has_value());
  EXPECT_TRUE(v6pkt->IsIPv6());
  EXPECT_EQ(v6pkt->size(), v6buf.size());
}