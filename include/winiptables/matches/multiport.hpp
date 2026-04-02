// Copyright (c) winiptables authors. All rights reserved.
// matches/multiport.hpp -- multiport extension: --sports/--dports multi-port and port range lists

#ifndef WINIPTABLES_MATCHES_MULTIPORT_HPP_
#define WINIPTABLES_MATCHES_MULTIPORT_HPP_

#include "winiptables/imatch.hpp"
#include "winiptables/packet.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace winiptables {

// Port range [min, max] (both in host byte order, min == max means single port)
struct PortRange {
  uint16_t min;
  uint16_t max;
};

// Matches -m multiport --sports/--dports <port[,port|port:port]...>
// Supports comma-separated port list and port ranges (e.g. "80,443,1024:2048").
class MultiportMatch final : public IMatch {
 public:
  // ranges: port range list; is_src: true=source port, false=destination port; negated: negation
  MultiportMatch(std::vector<PortRange> ranges, bool is_src,
                 bool negated = false)
      : ranges_(std::move(ranges)), is_src_(is_src), negated_(negated) {}

  [[nodiscard]] bool Matches(const Packet& packet,
                              const MatchContext& ctx) const override;
  [[nodiscard]] std::string ToRuleText() const override;

  // Parses "80,443,1024:2048" format port string, returns MultiportMatch instance.
  // Throws std::invalid_argument on parse failure.
  static std::unique_ptr<MultiportMatch> Parse(const std::string& ports_str,
                                               bool is_src,
                                               bool negated = false);

 private:
  std::vector<PortRange> ranges_;
  bool is_src_;
  bool negated_;
};

}  // namespace winiptables

#endif  // WINIPTABLES_MATCHES_MULTIPORT_HPP_