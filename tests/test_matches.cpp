// Copyright (c) winiptables authors. All rights reserved.
// test_matches.cpp -- Match condition property tests
//
// Validates Property 3 (negation symmetry):
//   forall packet, match: m.Matches(p) XOR neg_m.Matches(p) == true

#include <gtest/gtest.h>

#include "winiptables/matches/basic.hpp"
#include "winiptables/matches/tcp.hpp"
#include "winiptables/packet.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstring>

using namespace winiptables;

// -- Helper: construct IPv4 packet -------------------------------------------

static Packet MakePacket(uint8_t protocol,
                          const char* src_ip_str,
                          const char* dst_ip_str,
                          uint16_t src_port   = 0,
                          uint16_t dst_port   = 0,
                          uint8_t  tcp_flags  = 0,
                          uint8_t  icmp_type  = 0,
                          uint32_t iface_idx  = 1,
                          Direction dir       = Direction::kInbound) {
  Packet p{};
  p.af          = AddressFamily::kIPv4;
  p.protocol    = protocol;
  p.src_port    = src_port;
  p.dst_port    = dst_port;
  p.tcp_flags   = tcp_flags;
  p.icmp_type   = icmp_type;
  p.iface_index = iface_idx;
  p.direction   = dir;

  uint32_t addr_be = 0;
  inet_pton(AF_INET, src_ip_str, &addr_be);
  std::memcpy(p.src_ip.v4, &addr_be, 4);
  p.src_ip.af = AddressFamily::kIPv4;

  inet_pton(AF_INET, dst_ip_str, &addr_be);
  std::memcpy(p.dst_ip.v4, &addr_be, 4);
  p.dst_ip.af = AddressFamily::kIPv4;

  return p;
}

static const MatchContext kCtx{};

// ============================================================================
// ProtocolMatch
// ============================================================================

TEST(ProtocolMatch, MatchesTcp) {
  ProtocolMatch m(6);
  EXPECT_TRUE(m.Matches(MakePacket(6, "1.2.3.4", "5.6.7.8"), kCtx));
}

TEST(ProtocolMatch, DoesNotMatchUdpWhenTcpExpected) {
  ProtocolMatch m(6);
  EXPECT_FALSE(m.Matches(MakePacket(17, "1.2.3.4", "5.6.7.8"), kCtx));
}

TEST(ProtocolMatch, MatchesAll) {
  ProtocolMatch m(0);
  EXPECT_TRUE(m.Matches(MakePacket(6,  "1.2.3.4", "5.6.7.8"), kCtx));
  EXPECT_TRUE(m.Matches(MakePacket(17, "1.2.3.4", "5.6.7.8"), kCtx));
  EXPECT_TRUE(m.Matches(MakePacket(1,  "1.2.3.4", "5.6.7.8"), kCtx));
}

TEST(ProtocolMatch, NegatedMatchesTcp) {
  ProtocolMatch m(6, /*negated=*/true);
  EXPECT_FALSE(m.Matches(MakePacket(6,  "1.2.3.4", "5.6.7.8"), kCtx));
  EXPECT_TRUE(m.Matches(MakePacket(17, "1.2.3.4", "5.6.7.8"), kCtx));
}

// Property 3: Negation symmetry
TEST(ProtocolMatch, NegationSymmetry_Tcp) {
  const Packet p = MakePacket(6, "1.2.3.4", "5.6.7.8");
  ProtocolMatch m(6, false);
  ProtocolMatch neg(6, true);
  EXPECT_TRUE(m.Matches(p, kCtx) ^ neg.Matches(p, kCtx));
}

TEST(ProtocolMatch, NegationSymmetry_Udp) {
  const Packet p = MakePacket(17, "1.2.3.4", "5.6.7.8");
  ProtocolMatch m(6, false);
  ProtocolMatch neg(6, true);
  EXPECT_TRUE(m.Matches(p, kCtx) ^ neg.Matches(p, kCtx));
}

// ============================================================================
// SrcIpMatch / DstIpMatch
// ============================================================================

TEST(SrcIpMatch, MatchesAddressInSubnet) {
  auto [net, plen] = ParseCidr("192.168.1.0/24");
  SrcIpMatch m(net, plen);
  EXPECT_TRUE(m.Matches(MakePacket(6, "192.168.1.100", "10.0.0.1"), kCtx));
}

TEST(SrcIpMatch, DoesNotMatchAddressOutsideSubnet) {
  auto [net, plen] = ParseCidr("192.168.1.0/24");
  SrcIpMatch m(net, plen);
  EXPECT_FALSE(m.Matches(MakePacket(6, "192.168.2.1", "10.0.0.1"), kCtx));
}

TEST(SrcIpMatch, MatchesExactHost) {
  auto [net, plen] = ParseCidr("10.0.0.5");
  SrcIpMatch m(net, plen);
  EXPECT_TRUE(m.Matches(MakePacket(6, "10.0.0.5", "1.2.3.4"), kCtx));
  EXPECT_FALSE(m.Matches(MakePacket(6, "10.0.0.6", "1.2.3.4"), kCtx));
}

TEST(SrcIpMatch, MatchAll_ZeroPrefixLen) {
  auto [net, plen] = ParseCidr("0.0.0.0/0");
  SrcIpMatch m(net, plen);
  EXPECT_TRUE(m.Matches(MakePacket(6, "192.168.100.200", "1.2.3.4"), kCtx));
}

TEST(DstIpMatch, MatchesAddressInSubnet) {
  auto [net, plen] = ParseCidr("192.168.1.0/24");
  DstIpMatch m(net, plen);
  EXPECT_TRUE(m.Matches(MakePacket(6, "10.0.0.1", "192.168.1.100"), kCtx));
}

// Property 3: DstIpMatch negation symmetry
TEST(DstIpMatch, NegationSymmetry_InSubnet) {
  auto [net, plen] = ParseCidr("192.168.1.0/24");
  DstIpMatch m(net, plen, false);
  DstIpMatch neg(net, plen, true);
  const Packet p = MakePacket(6, "10.0.0.1", "192.168.1.100");
  EXPECT_TRUE(m.Matches(p, kCtx) ^ neg.Matches(p, kCtx));
}

TEST(DstIpMatch, NegationSymmetry_OutsideSubnet) {
  auto [net, plen] = ParseCidr("192.168.1.0/24");
  DstIpMatch m(net, plen, false);
  DstIpMatch neg(net, plen, true);
  const Packet p = MakePacket(6, "10.0.0.1", "10.0.0.2");
  EXPECT_TRUE(m.Matches(p, kCtx) ^ neg.Matches(p, kCtx));
}

// Property 3: SrcIpMatch negation symmetry
TEST(SrcIpMatch, NegationSymmetry_InSubnet) {
  auto [net, plen] = ParseCidr("192.168.1.0/24");
  SrcIpMatch m(net, plen, false);
  SrcIpMatch neg(net, plen, true);
  const Packet p = MakePacket(6, "192.168.1.100", "10.0.0.1");
  EXPECT_TRUE(m.Matches(p, kCtx) ^ neg.Matches(p, kCtx));
}

TEST(SrcIpMatch, NegationSymmetry_OutsideSubnet) {
  auto [net, plen] = ParseCidr("192.168.1.0/24");
  SrcIpMatch m(net, plen, false);
  SrcIpMatch neg(net, plen, true);
  const Packet p = MakePacket(6, "192.168.2.1", "10.0.0.1");
  EXPECT_TRUE(m.Matches(p, kCtx) ^ neg.Matches(p, kCtx));
}

// ============================================================================
// SrcPortMatch / DstPortMatch
// ============================================================================

TEST(SrcPortMatch, MatchesSinglePort) {
  SrcPortMatch m(80, 80);
  EXPECT_TRUE(m.Matches(MakePacket(6, "1.2.3.4", "5.6.7.8", 80, 0), kCtx));
}

TEST(SrcPortMatch, DoesNotMatchDifferentPort) {
  SrcPortMatch m(80, 80);
  EXPECT_FALSE(m.Matches(MakePacket(6, "1.2.3.4", "5.6.7.8", 443, 0), kCtx));
}

TEST(SrcPortMatch, MatchesPortInRange) {
  SrcPortMatch m(1024, 2048);
  EXPECT_TRUE(m.Matches(MakePacket(6, "1.2.3.4", "5.6.7.8", 1500, 0), kCtx));
  EXPECT_FALSE(m.Matches(MakePacket(6, "1.2.3.4", "5.6.7.8", 3000, 0), kCtx));
  EXPECT_TRUE(m.Matches(MakePacket(6, "1.2.3.4", "5.6.7.8", 1024, 0), kCtx));
  EXPECT_TRUE(m.Matches(MakePacket(6, "1.2.3.4", "5.6.7.8", 2048, 0), kCtx));
}

TEST(DstPortMatch, DoesNotMatchNonTcpUdp) {
  DstPortMatch m(80, 80);
  EXPECT_FALSE(m.Matches(MakePacket(1, "1.2.3.4", "5.6.7.8", 0, 80), kCtx));
}

// Property 3: SrcPortMatch negation symmetry
TEST(SrcPortMatch, NegationSymmetry_InRange) {
  SrcPortMatch m(1024, 2048, false);
  SrcPortMatch neg(1024, 2048, true);
  const Packet p = MakePacket(6, "1.2.3.4", "5.6.7.8", 1500, 0);
  EXPECT_TRUE(m.Matches(p, kCtx) ^ neg.Matches(p, kCtx));
}

TEST(SrcPortMatch, NegationSymmetry_OutOfRange) {
  SrcPortMatch m(1024, 2048, false);
  SrcPortMatch neg(1024, 2048, true);
  const Packet p = MakePacket(6, "1.2.3.4", "5.6.7.8", 3000, 0);
  EXPECT_TRUE(m.Matches(p, kCtx) ^ neg.Matches(p, kCtx));
}

// Property 3: DstPortMatch negation symmetry
TEST(DstPortMatch, NegationSymmetry_InRange) {
  DstPortMatch m(1024, 2048, false);
  DstPortMatch neg(1024, 2048, true);
  const Packet p = MakePacket(6, "1.2.3.4", "5.6.7.8", 0, 1500);
  EXPECT_TRUE(m.Matches(p, kCtx) ^ neg.Matches(p, kCtx));
}

TEST(DstPortMatch, NegationSymmetry_OutOfRange) {
  DstPortMatch m(1024, 2048, false);
  DstPortMatch neg(1024, 2048, true);
  const Packet p = MakePacket(6, "1.2.3.4", "5.6.7.8", 0, 3000);
  EXPECT_TRUE(m.Matches(p, kCtx) ^ neg.Matches(p, kCtx));
}

// ============================================================================
// TcpFlagsMatch
// ============================================================================

TEST(TcpFlagsMatch, ParseFlags_SynAck) {
  EXPECT_EQ(TcpFlagsMatch::ParseFlags("SYN,ACK"),
            tcp_flags::kSyn | tcp_flags::kAck);
}

TEST(TcpFlagsMatch, ParseFlags_None) {
  EXPECT_EQ(TcpFlagsMatch::ParseFlags("NONE"), 0u);
}

TEST(TcpFlagsMatch, ParseFlags_All) {
  EXPECT_EQ(TcpFlagsMatch::ParseFlags("ALL"), 0x3Fu);
}

TEST(TcpFlagsMatch, MatchesSynPacket) {
  TcpFlagsMatch m(tcp_flags::kSyn | tcp_flags::kAck, tcp_flags::kSyn);
  EXPECT_TRUE(m.Matches(
      MakePacket(6, "1.2.3.4", "5.6.7.8", 0, 0, tcp_flags::kSyn), kCtx));
}

TEST(TcpFlagsMatch, DoesNotMatchSynAckPacket) {
  TcpFlagsMatch m(tcp_flags::kSyn | tcp_flags::kAck, tcp_flags::kSyn);
  EXPECT_FALSE(m.Matches(
      MakePacket(6, "1.2.3.4", "5.6.7.8", 0, 0,
                 tcp_flags::kSyn | tcp_flags::kAck), kCtx));
}

TEST(TcpFlagsMatch, DoesNotMatchNonTcp) {
  TcpFlagsMatch m(tcp_flags::kSyn, tcp_flags::kSyn);
  EXPECT_FALSE(m.Matches(MakePacket(17, "1.2.3.4", "5.6.7.8"), kCtx));
}

// Property 3: TcpFlagsMatch negation symmetry
TEST(TcpFlagsMatch, NegationSymmetry_SynMatch) {
  TcpFlagsMatch m(tcp_flags::kSyn | tcp_flags::kAck, tcp_flags::kSyn, false);
  TcpFlagsMatch neg(tcp_flags::kSyn | tcp_flags::kAck, tcp_flags::kSyn, true);
  const Packet p = MakePacket(6, "1.2.3.4", "5.6.7.8", 0, 0, tcp_flags::kSyn);
  EXPECT_TRUE(m.Matches(p, kCtx) ^ neg.Matches(p, kCtx));
}

TEST(TcpFlagsMatch, NegationSymmetry_SynAckNoMatch) {
  TcpFlagsMatch m(tcp_flags::kSyn | tcp_flags::kAck, tcp_flags::kSyn, false);
  TcpFlagsMatch neg(tcp_flags::kSyn | tcp_flags::kAck, tcp_flags::kSyn, true);
  const Packet p = MakePacket(6, "1.2.3.4", "5.6.7.8", 0, 0,
                               tcp_flags::kSyn | tcp_flags::kAck);
  EXPECT_TRUE(m.Matches(p, kCtx) ^ neg.Matches(p, kCtx));
}

// ============================================================================
// IcmpTypeMatch
// ============================================================================

TEST(IcmpTypeMatch, MatchesEchoRequest) {
  IcmpTypeMatch m(8);
  Packet p = MakePacket(1, "1.2.3.4", "5.6.7.8");
  p.icmp_type = 8;
  EXPECT_TRUE(m.Matches(p, kCtx));
}

TEST(IcmpTypeMatch, DoesNotMatchDifferentType) {
  IcmpTypeMatch m(8);
  Packet p = MakePacket(1, "1.2.3.4", "5.6.7.8");
  p.icmp_type = 0;
  EXPECT_FALSE(m.Matches(p, kCtx));
}

TEST(IcmpTypeMatch, DoesNotMatchNonIcmp) {
  IcmpTypeMatch m(8);
  EXPECT_FALSE(m.Matches(MakePacket(6, "1.2.3.4", "5.6.7.8"), kCtx));
}

// Property 3: IcmpTypeMatch negation symmetry
TEST(IcmpTypeMatch, NegationSymmetry_Match) {
  IcmpTypeMatch m(8, false);
  IcmpTypeMatch neg(8, true);
  Packet p = MakePacket(1, "1.2.3.4", "5.6.7.8");
  p.icmp_type = 8;
  EXPECT_TRUE(m.Matches(p, kCtx) ^ neg.Matches(p, kCtx));
}

TEST(IcmpTypeMatch, NegationSymmetry_NoMatch) {
  IcmpTypeMatch m(8, false);
  IcmpTypeMatch neg(8, true);
  Packet p = MakePacket(1, "1.2.3.4", "5.6.7.8");
  p.icmp_type = 0;
  EXPECT_TRUE(m.Matches(p, kCtx) ^ neg.Matches(p, kCtx));
}

// ============================================================================
// InIfaceMatch / OutIfaceMatch
// ============================================================================

TEST(InIfaceMatch, MatchesInboundOnCorrectIface) {
  InIfaceMatch m(2);
  EXPECT_TRUE(m.Matches(
      MakePacket(6, "1.2.3.4", "5.6.7.8", 0, 0, 0, 0, 2, Direction::kInbound),
      kCtx));
}

TEST(InIFaceMatch, DoesNotMatchDifferentIface) {
  InIfaceMatch m(2);
  EXPECT_FALSE(m.Matches(
      MakePacket(6, "1.2.3.4", "5.6.7.8", 0, 0, 0, 0, 3, Direction::kInbound),
      kCtx));
}

TEST(InIfaceMatch, DoesNotMatchOutbound) {
  InIfaceMatch m(2);
  EXPECT_FALSE(m.Matches(
      MakePacket(6, "1.2.3.4", "5.6.7.8", 0, 0, 0, 0, 2, Direction::kOutbound),
      kCtx));
}

// Property 3: InIfaceMatch negation symmetry
TEST(InIfaceMatch, NegationSymmetry_Match) {
  InIfaceMatch m(2, false);
  InIfaceMatch neg(2, true);
  const Packet p = MakePacket(6, "1.2.3.4", "5.6.7.8", 0, 0, 0, 0, 2,
                               Direction::kInbound);
  EXPECT_TRUE(m.Matches(p, kCtx) ^ neg.Matches(p, kCtx));
}

TEST(InIfaceMatch, NegationSymmetry_NoMatch) {
  InIfaceMatch m(2, false);
  InIfaceMatch neg(2, true);
  const Packet p = MakePacket(6, "1.2.3.4", "5.6.7.8", 0, 0, 0, 0, 3,
                               Direction::kInbound);
  EXPECT_TRUE(m.Matches(p, kCtx) ^ neg.Matches(p, kCtx));
}

TEST(OutIfaceMatch, MatchesOutboundOnCorrectIface) {
  OutIfaceMatch m(2);
  EXPECT_TRUE(m.Matches(
      MakePacket(6, "1.2.3.4", "5.6.7.8", 0, 0, 0, 0, 2, Direction::kOutbound),
      kCtx));
}

TEST(OutIfaceMatch, DoesNotMatchInbound) {
  OutIfaceMatch m(2);
  EXPECT_FALSE(m.Matches(
      MakePacket(6, "1.2.3.4", "5.6.7.8", 0, 0, 0, 0, 2, Direction::kInbound),
      kCtx));
}

// Property 3: OutIfaceMatch negation symmetry
TEST(OutIfaceMatch, NegationSymmetry_Match) {
  OutIfaceMatch m(2, false);
  OutIfaceMatch neg(2, true);
  const Packet p = MakePacket(6, "1.2.3.4", "5.6.7.8", 0, 0, 0, 0, 2,
                               Direction::kOutbound);
  EXPECT_TRUE(m.Matches(p, kCtx) ^ neg.Matches(p, kCtx));
}

TEST(OutIfaceMatch, NegationSymmetry_NoMatch) {
  OutIfaceMatch m(2, false);
  OutIfaceMatch neg(2, true);
  const Packet p = MakePacket(6, "1.2.3.4", "5.6.7.8", 0, 0, 0, 0, 3,
                               Direction::kOutbound);
  EXPECT_TRUE(m.Matches(p, kCtx) ^ neg.Matches(p, kCtx));
}

// ============================================================================
// ToRuleText serialization
// ============================================================================

TEST(ProtocolMatch, ToRuleText_Tcp) {
  EXPECT_EQ(ProtocolMatch(6).ToRuleText(), "-p tcp");
}

TEST(ProtocolMatch, ToRuleText_NegatedUdp) {
  EXPECT_EQ(ProtocolMatch(17, true).ToRuleText(), "! -p udp");
}

TEST(SrcPortMatch, ToRuleText_Range) {
  EXPECT_EQ(SrcPortMatch(1024, 2048).ToRuleText(), "--sport 1024:2048");
}

TEST(DstPortMatch, ToRuleText_Single) {
  EXPECT_EQ(DstPortMatch(80, 80).ToRuleText(), "--dport 80");
}

TEST(TcpFlagsMatch, ToRuleText_SynOnly) {
  TcpFlagsMatch m(tcp_flags::kSyn | tcp_flags::kAck, tcp_flags::kSyn);
  EXPECT_EQ(m.ToRuleText(), "--tcp-flags SYN,ACK SYN");
}

TEST(IcmpTypeMatch, ToRuleText) {
  EXPECT_EQ(IcmpTypeMatch(8).ToRuleText(), "--icmp-type 8");
}

// ============================================================================
// MultiportMatch
// ============================================================================

#include "winiptables/matches/multiport.hpp"

TEST(MultiportMatch, MatchesSingleDstPort) {
  auto m = MultiportMatch::Parse("80", /*is_src=*/false);
  EXPECT_TRUE(m->Matches(MakePacket(6, "1.2.3.4", "5.6.7.8", 0, 80), kCtx));
  EXPECT_FALSE(m->Matches(MakePacket(6, "1.2.3.4", "5.6.7.8", 0, 443), kCtx));
}

TEST(MultiportMatch, MatchesMultipleDstPorts) {
  auto m = MultiportMatch::Parse("80,443", /*is_src=*/false);
  EXPECT_TRUE(m->Matches(MakePacket(6, "1.2.3.4", "5.6.7.8", 0, 80), kCtx));
  EXPECT_TRUE(m->Matches(MakePacket(6, "1.2.3.4", "5.6.7.8", 0, 443), kCtx));
  EXPECT_FALSE(m->Matches(MakePacket(6, "1.2.3.4", "5.6.7.8", 0, 8080), kCtx));
}

TEST(MultiportMatch, MatchesDstPortRange) {
  auto m = MultiportMatch::Parse("1024:2048", /*is_src=*/false);
  EXPECT_TRUE(m->Matches(MakePacket(6, "1.2.3.4", "5.6.7.8", 0, 1024), kCtx));
  EXPECT_TRUE(m->Matches(MakePacket(6, "1.2.3.4", "5.6.7.8", 0, 1500), kCtx));
  EXPECT_TRUE(m->Matches(MakePacket(6, "1.2.3.4", "5.6.7.8", 0, 2048), kCtx));
  EXPECT_FALSE(m->Matches(MakePacket(6, "1.2.3.4", "5.6.7.8", 0, 2049), kCtx));
}

TEST(MultiportMatch, MatchesMixedPortsAndRanges) {
  auto m = MultiportMatch::Parse("80,443,1024:2048", /*is_src=*/false);
  EXPECT_TRUE(m->Matches(MakePacket(6, "1.2.3.4", "5.6.7.8", 0, 80), kCtx));
  EXPECT_TRUE(m->Matches(MakePacket(6, "1.2.3.4", "5.6.7.8", 0, 443), kCtx));
  EXPECT_TRUE(m->Matches(MakePacket(6, "1.2.3.4", "5.6.7.8", 0, 1500), kCtx));
  EXPECT_FALSE(m->Matches(MakePacket(6, "1.2.3.4", "5.6.7.8", 0, 3000), kCtx));
}

TEST(MultiportMatch, MatchesSrcPort) {
  auto m = MultiportMatch::Parse("80,443", /*is_src=*/true);
  EXPECT_TRUE(m->Matches(MakePacket(6, "1.2.3.4", "5.6.7.8", 80, 0), kCtx));
  EXPECT_FALSE(m->Matches(MakePacket(6, "1.2.3.4", "5.6.7.8", 0, 80), kCtx));
}

TEST(MultiportMatch, DoesNotMatchNonTcpUdp) {
  auto m = MultiportMatch::Parse("80", /*is_src=*/false);
  EXPECT_FALSE(m->Matches(MakePacket(1, "1.2.3.4", "5.6.7.8", 0, 80), kCtx));
}

TEST(MultiportMatch, NegatedDoesNotMatchInList) {
  auto m = MultiportMatch::Parse("80,443", /*is_src=*/false, /*negated=*/true);
  EXPECT_FALSE(m->Matches(MakePacket(6, "1.2.3.4", "5.6.7.8", 0, 80), kCtx));
  EXPECT_TRUE(m->Matches(MakePacket(6, "1.2.3.4", "5.6.7.8", 0, 8080), kCtx));
}

// Property 3: MultiportMatch negation symmetry
TEST(MultiportMatch, NegationSymmetry_InList) {
  auto m   = MultiportMatch::Parse("80,443,1024:2048", false, false);
  auto neg = MultiportMatch::Parse("80,443,1024:2048", false, true);
  const Packet p = MakePacket(6, "1.2.3.4", "5.6.7.8", 0, 443);
  EXPECT_TRUE(m->Matches(p, kCtx) ^ neg->Matches(p, kCtx));
}

TEST(MultiportMatch, NegationSymmetry_OutOfList) {
  auto m   = MultiportMatch::Parse("80,443,1024:2048", false, false);
  auto neg = MultiportMatch::Parse("80,443,1024:2048", false, true);
  const Packet p = MakePacket(6, "1.2.3.4", "5.6.7.8", 0, 3000);
  EXPECT_TRUE(m->Matches(p, kCtx) ^ neg->Matches(p, kCtx));
}

TEST(MultiportMatch, ToRuleText_Dports) {
  auto m = MultiportMatch::Parse("80,443,1024:2048", /*is_src=*/false);
  EXPECT_EQ(m->ToRuleText(), "-m multiport --dports 80,443,1024:2048");
}

TEST(MultiportMatch, ToRuleText_Sports) {
  auto m = MultiportMatch::Parse("22,8080", /*is_src=*/true);
  EXPECT_EQ(m->ToRuleText(), "-m multiport --sports 22,8080");
}

TEST(MultiportMatch, ToRuleText_Negated) {
  auto m = MultiportMatch::Parse("80", /*is_src=*/false, /*negated=*/true);
  EXPECT_EQ(m->ToRuleText(), "! -m multiport --dports 80");
}