// test_parser.cpp — CommandParser unit tests (task 12.6)

#include "../src/cli/parser.hpp"

#include <gtest/gtest.h>
#include <vector>
#include <string>

using winiptables::cli::CommandParser;
using winiptables::cli::ParsedCommand;

// Helper: convert string array to argc/argv
struct ArgvHelper {
    std::vector<std::string> storage;
    std::vector<char*>       ptrs;

    explicit ArgvHelper(std::initializer_list<const char*> args) {
        for (const char* a : args) storage.emplace_back(a);
        for (auto& s : storage) ptrs.push_back(s.data());
    }

    int argc() const { return static_cast<int>(ptrs.size()); }
    char** argv() { return ptrs.data(); }
};

// -----------------------------------------------------------------------
// Basic verb parsing
// -----------------------------------------------------------------------

TEST(CommandParser, DefaultVerbIsListWhenNoArgs) {
    ArgvHelper args{"winiptables"};
    auto cmd = CommandParser::parse(args.argc(), args.argv());
    EXPECT_EQ(cmd.verb, "-L");
    EXPECT_TRUE(cmd.error.empty());
}

TEST(CommandParser, AppendRule) {
    ArgvHelper args{"winiptables", "-A", "INPUT", "-p", "tcp", "--dport", "80", "-j", "ACCEPT"};
    auto cmd = CommandParser::parse(args.argc(), args.argv());
    EXPECT_EQ(cmd.verb, "-A");
    EXPECT_EQ(cmd.chain, "INPUT");
    EXPECT_EQ(cmd.table, "filter");
    ASSERT_GE(cmd.rule_args.size(), 5u);
    EXPECT_TRUE(cmd.error.empty());
}

TEST(CommandParser, InsertRuleWithNumber) {
    ArgvHelper args{"winiptables", "-I", "FORWARD", "3", "-j", "DROP"};
    auto cmd = CommandParser::parse(args.argc(), args.argv());
    EXPECT_EQ(cmd.verb, "-I");
    EXPECT_EQ(cmd.chain, "FORWARD");
    EXPECT_EQ(cmd.rule_num, 3);
    EXPECT_TRUE(cmd.error.empty());
}

TEST(CommandParser, InsertRuleDefaultNumber) {
    ArgvHelper args{"winiptables", "-I", "INPUT", "-j", "ACCEPT"};
    auto cmd = CommandParser::parse(args.argc(), args.argv());
    EXPECT_EQ(cmd.verb, "-I");
    EXPECT_EQ(cmd.chain, "INPUT");
    EXPECT_EQ(cmd.rule_num, 1);
}

TEST(CommandParser, DeleteRuleByNumber) {
    ArgvHelper args{"winiptables", "-D", "OUTPUT", "2"};
    auto cmd = CommandParser::parse(args.argc(), args.argv());
    EXPECT_EQ(cmd.verb, "-D");
    EXPECT_EQ(cmd.chain, "OUTPUT");
    EXPECT_EQ(cmd.rule_num, 2);
}

TEST(CommandParser, ReplaceRule) {
    ArgvHelper args{"winiptables", "-R", "INPUT", "1", "-j", "DROP"};
    auto cmd = CommandParser::parse(args.argc(), args.argv());
    EXPECT_EQ(cmd.verb, "-R");
    EXPECT_EQ(cmd.chain, "INPUT");
    EXPECT_EQ(cmd.rule_num, 1);
}

TEST(CommandParser, ListChain) {
    ArgvHelper args{"winiptables", "-L", "INPUT"};
    auto cmd = CommandParser::parse(args.argc(), args.argv());
    EXPECT_EQ(cmd.verb, "-L");
    EXPECT_EQ(cmd.chain, "INPUT");
}

TEST(CommandParser, ListAllChains) {
    ArgvHelper args{"winiptables", "-L"};
    auto cmd = CommandParser::parse(args.argc(), args.argv());
    EXPECT_EQ(cmd.verb, "-L");
    EXPECT_TRUE(cmd.chain.empty());
}

TEST(CommandParser, FlushChain) {
    ArgvHelper args{"winiptables", "-F", "FORWARD"};
    auto cmd = CommandParser::parse(args.argc(), args.argv());
    EXPECT_EQ(cmd.verb, "-F");
    EXPECT_EQ(cmd.chain, "FORWARD");
}

TEST(CommandParser, ZeroCounters) {
    ArgvHelper args{"winiptables", "-Z"};
    auto cmd = CommandParser::parse(args.argc(), args.argv());
    EXPECT_EQ(cmd.verb, "-Z");
}

TEST(CommandParser, NewChain) {
    ArgvHelper args{"winiptables", "-N", "MYCHAIN"};
    auto cmd = CommandParser::parse(args.argc(), args.argv());
    EXPECT_EQ(cmd.verb, "-N");
    EXPECT_EQ(cmd.chain, "MYCHAIN");
}

TEST(CommandParser, DeleteChain) {
    ArgvHelper args{"winiptables", "-X", "MYCHAIN"};
    auto cmd = CommandParser::parse(args.argc(), args.argv());
    EXPECT_EQ(cmd.verb, "-X");
    EXPECT_EQ(cmd.chain, "MYCHAIN");
}

TEST(CommandParser, SetPolicy) {
    ArgvHelper args{"winiptables", "-P", "INPUT", "DROP"};
    auto cmd = CommandParser::parse(args.argc(), args.argv());
    EXPECT_EQ(cmd.verb, "-P");
    EXPECT_EQ(cmd.chain, "INPUT");
    ASSERT_FALSE(cmd.rule_args.empty());
    EXPECT_EQ(cmd.rule_args[0], "DROP");
}

TEST(CommandParser, RenameChain) {
    ArgvHelper args{"winiptables", "-E", "OLDNAME", "NEWNAME"};
    auto cmd = CommandParser::parse(args.argc(), args.argv());
    EXPECT_EQ(cmd.verb, "-E");
    EXPECT_EQ(cmd.chain, "OLDNAME");
    ASSERT_FALSE(cmd.rule_args.empty());
    EXPECT_EQ(cmd.rule_args[0], "NEWNAME");
}

// -----------------------------------------------------------------------
// Table option -t
// -----------------------------------------------------------------------

TEST(CommandParser, TableOption) {
    ArgvHelper args{"winiptables", "-t", "nat", "-L"};
    auto cmd = CommandParser::parse(args.argc(), args.argv());
    EXPECT_EQ(cmd.table, "nat");
    EXPECT_EQ(cmd.verb, "-L");
}

TEST(CommandParser, TableLongOption) {
    ArgvHelper args{"winiptables", "--table", "mangle", "-F"};
    auto cmd = CommandParser::parse(args.argc(), args.argv());
    EXPECT_EQ(cmd.table, "mangle");
    EXPECT_EQ(cmd.verb, "-F");
}

TEST(CommandParser, DefaultTableIsFilter) {
    ArgvHelper args{"winiptables", "-L"};
    auto cmd = CommandParser::parse(args.argc(), args.argv());
    EXPECT_EQ(cmd.table, "filter");
}

// -----------------------------------------------------------------------
// Output options
// -----------------------------------------------------------------------

TEST(CommandParser, NumericOption) {
    ArgvHelper args{"winiptables", "-L", "-n"};
    auto cmd = CommandParser::parse(args.argc(), args.argv());
    EXPECT_TRUE(cmd.numeric);
}

TEST(CommandParser, VerboseOption) {
    ArgvHelper args{"winiptables", "-L", "-v"};
    auto cmd = CommandParser::parse(args.argc(), args.argv());
    EXPECT_TRUE(cmd.verbose);
}

TEST(CommandParser, LineNumbersOption) {
    ArgvHelper args{"winiptables", "-L", "--line-numbers"};
    auto cmd = CommandParser::parse(args.argc(), args.argv());
    EXPECT_TRUE(cmd.line_numbers);
}

TEST(CommandParser, CombinedOutputOptions) {
    ArgvHelper args{"winiptables", "-L", "-n", "-v", "--line-numbers"};
    auto cmd = CommandParser::parse(args.argc(), args.argv());
    EXPECT_TRUE(cmd.numeric);
    EXPECT_TRUE(cmd.verbose);
    EXPECT_TRUE(cmd.line_numbers);
}

// -----------------------------------------------------------------------
// service subcommand
// -----------------------------------------------------------------------

TEST(CommandParser, ServiceInstall) {
    ArgvHelper args{"winiptables", "service", "install"};
    auto cmd = CommandParser::parse(args.argc(), args.argv());
    EXPECT_EQ(cmd.service_action, "install");
    EXPECT_TRUE(cmd.error.empty());
}

TEST(CommandParser, ServiceStart) {
    ArgvHelper args{"winiptables", "service", "start"};
    auto cmd = CommandParser::parse(args.argc(), args.argv());
    EXPECT_EQ(cmd.service_action, "start");
}

TEST(CommandParser, ServiceStop) {
    ArgvHelper args{"winiptables", "service", "stop"};
    auto cmd = CommandParser::parse(args.argc(), args.argv());
    EXPECT_EQ(cmd.service_action, "stop");
}

TEST(CommandParser, ServiceUninstall) {
    ArgvHelper args{"winiptables", "service", "uninstall"};
    auto cmd = CommandParser::parse(args.argc(), args.argv());
    EXPECT_EQ(cmd.service_action, "uninstall");
}

TEST(CommandParser, ServiceMissingAction) {
    ArgvHelper args{"winiptables", "service"};
    auto cmd = CommandParser::parse(args.argc(), args.argv());
    EXPECT_FALSE(cmd.error.empty());
}

TEST(CommandParser, ServiceUnknownAction) {
    ArgvHelper args{"winiptables", "service", "restart"};
    auto cmd = CommandParser::parse(args.argc(), args.argv());
    EXPECT_FALSE(cmd.error.empty());
}

// -----------------------------------------------------------------------
// iptables-save / iptables-restore (detected via program name)
// -----------------------------------------------------------------------

TEST(CommandParser, IptablesSaveByProgName) {
    ArgvHelper args{"iptables-save"};
    auto cmd = CommandParser::parse(args.argc(), args.argv());
    EXPECT_TRUE(cmd.is_save);
    EXPECT_FALSE(cmd.is_restore);
}

TEST(CommandParser, IptablesRestoreByProgName) {
    ArgvHelper args{"iptables-restore"};
    auto cmd = CommandParser::parse(args.argc(), args.argv());
    EXPECT_TRUE(cmd.is_restore);
    EXPECT_FALSE(cmd.is_save);
}

TEST(CommandParser, IptablesSaveWithExeSuffix) {
    ArgvHelper args{"iptables-save.exe"};
    auto cmd = CommandParser::parse(args.argc(), args.argv());
    EXPECT_TRUE(cmd.is_save);
}

TEST(CommandParser, IptablesRestoreNoflush) {
    ArgvHelper args{"iptables-restore", "--noflush"};
    auto cmd = CommandParser::parse(args.argc(), args.argv());
    EXPECT_TRUE(cmd.is_restore);
    EXPECT_TRUE(cmd.noflush);
}

TEST(CommandParser, IptablesRestoreWithFile) {
    ArgvHelper args{"iptables-restore", "-f", "rules.txt"};
    auto cmd = CommandParser::parse(args.argc(), args.argv());
    EXPECT_TRUE(cmd.is_restore);
    EXPECT_EQ(cmd.file_path, "rules.txt");
}

// -----------------------------------------------------------------------
// Long option aliases
// -----------------------------------------------------------------------

TEST(CommandParser, LongOptionAppend) {
    ArgvHelper args{"winiptables", "--append", "INPUT", "-j", "ACCEPT"};
    auto cmd = CommandParser::parse(args.argc(), args.argv());
    EXPECT_EQ(cmd.verb, "-A");
    EXPECT_EQ(cmd.chain, "INPUT");
}

TEST(CommandParser, LongOptionList) {
    ArgvHelper args{"winiptables", "--list"};
    auto cmd = CommandParser::parse(args.argc(), args.argv());
    EXPECT_EQ(cmd.verb, "-L");
}

TEST(CommandParser, LongOptionFlush) {
    ArgvHelper args{"winiptables", "--flush"};
    auto cmd = CommandParser::parse(args.argc(), args.argv());
    EXPECT_EQ(cmd.verb, "-F");
}

// -----------------------------------------------------------------------
// Rule argument collection
// -----------------------------------------------------------------------

TEST(CommandParser, RuleArgsCollected) {
    ArgvHelper args{"winiptables", "-A", "INPUT",
                    "-p", "tcp", "-s", "192.168.1.0/24",
                    "--dport", "443", "-j", "ACCEPT"};
    auto cmd = CommandParser::parse(args.argc(), args.argv());
    EXPECT_EQ(cmd.verb, "-A");
    EXPECT_EQ(cmd.chain, "INPUT");
    // Rule args should contain: -p tcp -s 192.168.1.0/24 --dport 443 -j ACCEPT
    EXPECT_GE(cmd.rule_args.size(), 7u);
}
