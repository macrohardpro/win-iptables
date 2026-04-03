#pragma once
// persist.hpp -- Rule persistence declarations (Task 11.1)
//
// RulePersist provides three static methods:
//   save()       -- Synchronously serialize RuleStore to iptables-save compatible format
//   load()       -- Synchronously parse iptables-save format file and load into RuleStore
//   save_async() -- Asynchronous save (std::async), does not block packet processing

#include "winiptables/rule_store.hpp"

#include <future>
#include <string>

namespace winiptables {

class RulePersist {
public:
    // -----------------------------------------------------------------------
    // Synchronous save (Task 11.2)
    // Serialize all tables from RuleStore to iptables-save compatible format and write to path.
    // Returns true on success, false on file I/O failure.
    // -----------------------------------------------------------------------
    static bool save(const RuleStore& store, const std::string& path);

    // -----------------------------------------------------------------------
    // Synchronous load (Task 11.3 / 11.4)
    // Parse iptables-save format file and load into store.
    //   noflush=false (default): Clear all rules in corresponding tables before loading
    //   noflush=true         : Append to existing rules, do not clear
    // On syntax error, outputs "Error at line N: <message>" and returns false.
    // -----------------------------------------------------------------------
    static bool load(RuleStore& store, const std::string& path,
                     bool noflush = false);

    // -----------------------------------------------------------------------
    // Asynchronous save (Task 11.5)
    // Execute save() in background thread, return std::future<bool> immediately.
    // -----------------------------------------------------------------------
    static std::future<bool> save_async(const RuleStore& store,
                                        const std::string& path);

    // Serialize a single table to iptables-save format, append to out
    static void serialize_table(const RuleStore& store, TableKind kind,
                                 const std::string& table_name,
                                 std::string& out);

private:
    // Serialize Target to "-j TARGET [args]" string
    static std::string target_to_text(const Target& target);
};

}  // namespace winiptables