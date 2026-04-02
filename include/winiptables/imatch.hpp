#pragma once
// imatch.hpp -- IMatch interface + MatchExtRegistry

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace winiptables {

struct Packet;
struct MatchContext {};

class IMatch {
public:
    virtual ~IMatch() = default;
    virtual bool Matches(const Packet& packet, const MatchContext& ctx) const = 0;
    virtual std::string ToRuleText() const = 0;
};

class IMatchExtFactory {
public:
    virtual ~IMatchExtFactory() = default;
    virtual std::unique_ptr<IMatch> Create(const std::vector<std::string>& args) const = 0;
};

class MatchExtRegistry {
public:
    void RegisterModule(const std::string& name,
                        std::unique_ptr<IMatchExtFactory> factory);
    std::unique_ptr<IMatch> Parse(const std::string& module,
                                  const std::vector<std::string>& args) const;

    // Register built-in extension modules (multiport, state)
    void RegisterBuiltinModules();

private:
    std::unordered_map<std::string, std::unique_ptr<IMatchExtFactory>> modules_;
};

}  // namespace winiptables
