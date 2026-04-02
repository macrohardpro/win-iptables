// Copyright (c) winiptables authors. All rights reserved.
// model.cpp -- MatchExtRegistry implementation

#include "winiptables/imatch.hpp"
#include "winiptables/matches/multiport.hpp"
#include "winiptables/matches/state.hpp"

#include <stdexcept>

namespace winiptables {

void MatchExtRegistry::RegisterModule(const std::string& name,
                                      std::unique_ptr<IMatchExtFactory> factory) {
  modules_[name] = std::move(factory);
}

std::unique_ptr<IMatch> MatchExtRegistry::Parse(
    const std::string& module,
    const std::vector<std::string>& args) const {
  auto it = modules_.find(module);
  if (it == modules_.end()) {
    throw std::runtime_error("Unknown match extension module: " + module);
  }
  return it->second->Create(args);
}

// -- MultiportMatchFactory ----------------------------------------------------

// Parses args format: ["--sports", "80,443"] or ["--dports", "1024:2048"]
// Optional leading "!" for negation: ["!", "--dports", "80"]
class MultiportMatchFactory final : public IMatchExtFactory {
 public:
  std::unique_ptr<IMatch> Create(const std::vector<std::string>& args) const override {
    bool negated = false;
    size_t idx = 0;

    if (!args.empty() && args[0] == "!") {
      negated = true;
      idx = 1;
    }

    if (idx + 1 >= args.size()) {
      throw std::invalid_argument(
          "multiport: expected --sports or --dports followed by port list");
    }

    const std::string& flag = args[idx];
    const std::string& ports_str = args[idx + 1];

    bool is_src;
    if (flag == "--sports" || flag == "--source-ports") {
      is_src = true;
    } else if (flag == "--dports" || flag == "--destination-ports") {
      is_src = false;
    } else {
      throw std::invalid_argument(
          "multiport: unknown flag '" + flag + "', expected --sports or --dports");
    }

    return MultiportMatch::Parse(ports_str, is_src, negated);
  }
};

// -- StateMatchFactory --------------------------------------------------------

// Parses args format: ["--state", "NEW,ESTABLISHED"]
// Optional leading "!" for negation: ["!", "--state", "NEW"]
class StateMatchFactory final : public IMatchExtFactory {
 public:
  std::unique_ptr<IMatch> Create(const std::vector<std::string>& args) const override {
    bool negated = false;
    size_t idx = 0;

    if (!args.empty() && args[0] == "!") {
      negated = true;
      idx = 1;
    }

    if (idx + 1 >= args.size()) {
      throw std::invalid_argument(
          "state: expected --state followed by state list");
    }

    const std::string& flag = args[idx];
    const std::string& states_str = args[idx + 1];

    if (flag != "--state") {
      throw std::invalid_argument(
          "state: unknown flag '" + flag + "', expected --state");
    }

    return StateMatch::Parse(states_str, negated);
  }
};

// ── Registration ──────────────────────────────────────────────────────────────

void MatchExtRegistry::RegisterBuiltinModules() {
  RegisterModule("multiport", std::make_unique<MultiportMatchFactory>());
  RegisterModule("state",     std::make_unique<StateMatchFactory>());
}

}  // namespace winiptables
