#pragma once
// rule_builder.hpp -- Shared rule argument parser used by both the
// command dispatcher and the persistence layer.

#include "winiptables/model.hpp"

#include <string>
#include <vector>

namespace winiptables {

// Parse a list of iptables rule arguments (everything after the chain name)
// into a Rule with fully populated matches and target.
// On error, sets err and returns a default-constructed Rule.
[[nodiscard]] Rule BuildRule(const std::vector<std::string>& rule_args,
                              std::string& err);

}  // namespace winiptables
