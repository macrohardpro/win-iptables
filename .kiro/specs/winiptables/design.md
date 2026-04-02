# 设计文档

## 概述

winiptables 是一个运行在 Windows 平台的 iptables 移植工具，采用 **Windows 服务 + CLI 客户端** 的双进程架构。
后台服务（`winiptables-svc`）持续运行，通过 WinDivert 捕获数据包并由规则引擎实时过滤；
CLI 工具（`winiptables`）通过命名管道与服务通信，发送规则管理命令并接收执行结果。

整体技术栈：**C++17/20**（核心实现）+ **WinDivert**（数据包捕获）+ **Windows Named Pipe**（IPC）+ **CMake**（构建系统）。

---

## 架构

```
┌─────────────────────────────────────────────────────────┐
│                   CLI 进程 (winiptables.exe)              │
│  CommandParser → IPC Client (Named Pipe) → 输出结果      │
└──────────────────────────┬──────────────────────────────┘
                           │ Named Pipe: \\.\pipe\winiptables
┌──────────────────────────▼──────────────────────────────┐
│              后台服务进程 (winiptables-svc.exe)            │
│                                                          │
│  IPC Server ──→ CommandDispatcher ──→ RuleStore          │
│                                            │             │
│  PacketCapture (WinDivert)                 │             │
│       │                                   ▼             │
│       └──────────────→ RuleEngine ←── TablePipeline     │
│                            │                             │
│                     PacketInjector                       │
└─────────────────────────────────────────────────────────┘
```

### 核心组件

| 组件 | 职责 |
|------|------|
| `CommandParser` | 解析 iptables 兼容的 CLI 参数，生成命令结构体 |
| `IPC Client/Server` | 基于 Windows 命名管道的进程间通信 |
| `CommandDispatcher` | 接收 IPC 命令，路由到对应的 RuleStore 操作 |
| `RuleStore` | 线程安全的规则存储，管理所有表/链/规则 |
| `TablePipeline` | 按 raw→mangle→nat→filter 顺序编排表处理逻辑 |
| `RuleEngine` | 对数据包执行规则匹配和目标动作 |
| `PacketCapture` | 基于 WinDivert 捕获 IPv4/IPv6 数据包 |
| `PacketInjector` | 将 ACCEPT 的数据包重新注入网络栈 |
| `StatefulTracker` | 连接状态跟踪（conntrack） |
| `MatchExtRegistry` | 扩展匹配模块插件注册表 |

---

## 组件详细设计

### 1. 数据模型

```cpp
// 表类型（raw 预留，当前不实现）
enum class TableKind { Raw, Mangle, Nat, Filter };

// 内置链
enum class BuiltinChain {
    Input, Output, Forward,
    Prerouting, Postrouting,
};

// ICMP 类型（用于 REJECT）
struct IcmpType {
    uint8_t type;
    uint8_t code;
};

// 目标动作
struct Target {
    enum class Kind {
        Accept, Drop, Reject, Return, Log,
        Jump, Masquerade, Dnat, Snat
    };
    Kind kind;
    // REJECT
    IcmpType reject_with{};
    // LOG
    std::string log_prefix;
    uint8_t     log_level{};
    // JUMP
    std::string jump_chain;
    // DNAT / SNAT
    std::string to_addr;  // "ip:port" 格式
};

// 规则计数器
struct RuleCounters {
    std::atomic<uint64_t> packets{0};
    std::atomic<uint64_t> bytes{0};
    void increment(uint64_t pkt_size) {
        packets.fetch_add(1, std::memory_order_relaxed);
        bytes.fetch_add(pkt_size, std::memory_order_relaxed);
    }
};

// 规则（前向声明 Match 接口）
struct Rule {
    std::vector<std::unique_ptr<IMatch>> matches;  // 匹配条件列表
    Target                               target;
    RuleCounters                         counters;
};

// 链
struct Chain {
    std::string        name;
    std::optional<Target> policy;   // 仅内置链有默认策略
    std::vector<Rule>  rules;
};

// 表
struct Table {
    TableKind                          kind;
    std::unordered_map<std::string, Chain> chains;
};
```

### 2. 匹配条件插件架构

所有匹配条件实现统一的 `IMatch` 纯虚接口，支持后续扩展：

```cpp
// 数据包上下文（前向声明）
struct Packet;
struct MatchContext;

// 匹配条件纯虚接口
class IMatch {
public:
    virtual ~IMatch() = default;
    /// 判断数据包是否匹配
    virtual bool matches(const Packet& packet, const MatchContext& ctx) const = 0;
    /// 序列化为 iptables 规则文本
    virtual std::string to_rule_text() const = 0;
};

// 扩展模块工厂纯虚接口
class IMatchExtFactory {
public:
    virtual ~IMatchExtFactory() = default;
    virtual std::unique_ptr<IMatch> create(const std::vector<std::string>& args) const = 0;
};

// 扩展模块注册表（插件化架构）
class MatchExtRegistry {
public:
    /// 注册扩展模块（如 limit、string、iprange 等后续扩展点）
    void register_module(const std::string& name,
                         std::unique_ptr<IMatchExtFactory> factory);
    std::unique_ptr<IMatch> parse(const std::string& module,
                                  const std::vector<std::string>& args) const;
private:
    std::unordered_map<std::string, std::unique_ptr<IMatchExtFactory>> modules_;
};
```

内置模块：`multiport`、`state`。预留接口供后续添加 `limit`、`string`、`iprange` 等。

### 3. 表处理管道（TablePipeline）

```cpp
enum class Verdict { Accept, Drop, Return };

class TablePipeline {
public:
    Verdict process(Packet& packet, PipelineContext& ctx) const {
        // 1. raw 表（预留，当前跳过）
        if (raw_) {
            if (eval_table(*raw_, packet, ctx) == Verdict::Drop)
                return Verdict::Drop;
        }
        // 2. mangle 表
        if (eval_table(mangle_, packet, ctx) == Verdict::Drop)
            return Verdict::Drop;
        // 3. nat 表
        if (eval_table(nat_, packet, ctx) == Verdict::Drop)
            return Verdict::Drop;
        // 4. filter 表
        return eval_table(filter_, packet, ctx);
    }

private:
    std::optional<Table> raw_;    // 预留扩展点，当前为 nullopt
    Table mangle_;
    Table nat_;
    Table filter_;

    Verdict eval_table(const Table& table, Packet& packet,
                       PipelineContext& ctx) const;
};
```

### 4. RuleEngine

```cpp
class RuleEngine {
public:
    /// 在指定链中评估数据包，返回最终裁决
    Verdict evaluate(const std::string& chain_name,
                     const Packet& packet,
                     EvalContext& ctx) const {
        const Chain* chain = rule_store_.get_chain(chain_name);
        if (!chain) return Verdict::Drop;

        for (const auto& rule : chain->rules) {
            if (matches_all(rule, packet, ctx)) {
                rule.counters.increment(packet.size());
                switch (rule.target.kind) {
                    case Target::Kind::Accept:
                        return Verdict::Accept;
                    case Target::Kind::Drop:
                        return Verdict::Drop;
                    case Target::Kind::Return:
                        return Verdict::Return;
                    case Target::Kind::Jump: {
                        Verdict v = evaluate(rule.target.jump_chain, packet, ctx);
                        if (v == Verdict::Return) continue;  // 继续当前链
                        return v;
                    }
                    default:
                        execute_action(rule.target, packet, ctx);
                        break;  // 继续评估后续规则
                }
            }
        }
        // 无规则匹配，使用默认策略
        if (chain->policy.has_value())
            return verdict_from_target(*chain->policy);
        return Verdict::Return;
    }

private:
    const RuleStore& rule_store_;
    bool matches_all(const Rule& rule, const Packet& pkt, EvalContext& ctx) const;
    void execute_action(const Target& target, const Packet& pkt, EvalContext& ctx) const;
    static Verdict verdict_from_target(const Target& t);
};
```

### 5. PacketCapture（IPv4 + IPv6）

```cpp
class PacketCapture {
public:
    explicit PacketCapture(HANDLE windivert_handle)
        : handle_(windivert_handle) {}

    ~PacketCapture() {
        if (handle_ != INVALID_HANDLE_VALUE)
            WinDivertClose(handle_);
    }

    // 不可复制，可移动
    PacketCapture(const PacketCapture&) = delete;
    PacketCapture& operator=(const PacketCapture&) = delete;

    struct CapturedPacket {
        Packet            packet;
        WINDIVERT_ADDRESS addr;
    };

    /// 捕获下一个数据包（IPv4 或 IPv6），阻塞直到有数据包到达
    std::optional<CapturedPacket> recv();

    /// 重新注入数据包
    bool inject(const Packet& packet, const WINDIVERT_ADDRESS& addr);

private:
    HANDLE handle_;
};
```

WinDivert 过滤器同时捕获 IPv4 和 IPv6：`"ip or ipv6"`。

### 6. IPC 通信协议

使用 Windows 命名管道 `\\.\pipe\winiptables`，消息格式为 JSON Lines（每条消息一行）：

```json
// 请求（CLI → 服务）
{ "id": "uuid", "argv": ["-t", "filter", "-A", "INPUT", "-p", "tcp", "--dport", "80", "-j", "ACCEPT"] }

// 响应（服务 → CLI）
{ "id": "uuid", "exit_code": 0, "stdout": "...", "stderr": "" }
```

服务端为每个 CLI 连接创建独立线程处理请求，规则操作通过 `std::shared_mutex` 保证线程安全（读操作使用 `shared_lock`，写操作使用 `unique_lock`）。

### 7. RuleStore（线程安全规则存储）

```cpp
class RuleStore {
public:
    // 读操作（-L）：获取共享锁
    std::vector<const Chain*> list_chains(TableKind table) const {
        std::shared_lock lock(mutex_);
        return list_chains_impl(table);
    }

    // 写操作（-A/-D/-I 等）：获取独占锁
    bool append_rule(TableKind table, const std::string& chain, Rule rule) {
        std::unique_lock lock(mutex_);
        return append_rule_impl(table, chain, std::move(rule));
    }

    const Chain* get_chain(const std::string& name) const;

private:
    mutable std::shared_mutex                    mutex_;
    std::unordered_map<TableKind, Table>         tables_;

    std::vector<const Chain*> list_chains_impl(TableKind table) const;
    bool append_rule_impl(TableKind table, const std::string& chain, Rule rule);
};

// 服务中以 std::shared_ptr<RuleStore> 共享，规则变更后原子替换
// 确保 PacketCapture 线程不中断
```

### 8. 规则持久化

持久化文件路径：`%ProgramData%\winiptables\rules.v4`（IPv4）和 `rules.v6`（IPv6）。

格式与 `iptables-save` 输出完全兼容：

```
# Generated by winiptables
*filter
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
-A INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
```

服务启动时自动加载，规则变更后异步写入（不阻塞数据包处理）。

### 9. Windows 服务管理

```
# 安装服务
winiptables service install

# 启动/停止
winiptables service start
winiptables service stop

# 卸载
winiptables service uninstall
```

服务通过 Windows Service Control Manager API（`CreateService`、`StartServiceCtrlDispatcher` 等）实现，注册为自动启动类型，以 LocalSystem 权限运行（WinDivert 需要）。

---

## 目录结构

```
winiptables/
├── CMakeLists.txt                  # 顶层 CMake 构建文件
├── cmake/
│   └── FindWinDivert.cmake         # WinDivert 查找模块
├── include/
│   └── winiptables/
│       ├── model.hpp               # 数据模型（TableKind、Chain、Rule、Target 等）
│       ├── imatch.hpp              # IMatch 纯虚接口 + MatchExtRegistry
│       ├── rule_store.hpp          # RuleStore 声明
│       ├── rule_engine.hpp         # RuleEngine 声明
│       ├── table_pipeline.hpp      # TablePipeline 声明
│       ├── packet.hpp              # IPv4/IPv6 数据包解析
│       ├── capture.hpp             # PacketCapture 声明
│       ├── stateful.hpp            # StatefulTracker 声明
│       └── persist.hpp             # 规则持久化声明
├── src/
│   ├── core/                       # 共享核心库（编译为静态库）
│   │   ├── CMakeLists.txt
│   │   ├── model.cpp
│   │   ├── rule_store.cpp
│   │   ├── rule_engine.cpp
│   │   ├── table_pipeline.cpp
│   │   ├── packet.cpp
│   │   ├── capture.cpp
│   │   ├── stateful.cpp
│   │   ├── persist.cpp
│   │   └── matches/
│   │       ├── basic.cpp           # -s/-d/-p/-i/-o 等基础匹配
│   │       ├── tcp.cpp             # TCP flags/ports
│   │       ├── multiport.cpp       # -m multiport
│   │       └── state.cpp           # -m state
│   ├── cli/                        # CLI 可执行文件
│   │   ├── CMakeLists.txt
│   │   ├── main.cpp
│   │   ├── parser.cpp              # 命令行参数解析
│   │   └── ipc_client.cpp          # 命名管道客户端
│   └── service/                    # 服务可执行文件
│       ├── CMakeLists.txt
│       ├── main.cpp
│       ├── service.cpp             # Windows 服务入口
│       ├── ipc_server.cpp          # 命名管道服务端
│       └── command_dispatcher.cpp  # 命令分发
├── tests/
│   ├── CMakeLists.txt
│   ├── test_rule_store.cpp
│   ├── test_rule_engine.cpp
│   ├── test_packet_parse.cpp
│   ├── test_persist.cpp
│   └── test_matches.cpp
├── third_party/
│   └── windivert/                  # WinDivert 头文件与库
└── README.md
```

---

## 正确性属性

基于需求分析，以下属性应通过属性测试（Property-Based Testing）验证：

### 属性 1：规则持久化往返属性（Round-Trip）

对于任意合法的 `Ruleset`，执行 `save` 后再执行 `restore` 必须产生等价的规则集：

```
∀ ruleset: parse(format(ruleset)) == ruleset
```

### 属性 2：规则顺序不变量

规则引擎必须严格按链中规则的顺序评估，第一条匹配规则的目标动作决定最终裁决：

```
∀ packet, chain: evaluate(chain, packet) == evaluate_first_match(chain, packet)
```

### 属性 3：匹配取反对称性

对于任意数据包和匹配条件 `m`，`m` 与 `!m` 的匹配结果必须互斥且完备：

```
∀ packet, match: matches(packet, m) XOR matches(packet, negate(m))
```

### 属性 4：计数器单调递增不变量

规则计数器只能递增，不能因规则评估而减少：

```
∀ rule: counter_after >= counter_before
```

### 属性 5：IPv4/IPv6 分类不变量

解析后的数据包地址族必须与原始数据包一致，IPv4 包不会被误判为 IPv6：

```
∀ raw_packet: parse(raw_packet).is_ipv6() == raw_packet.is_ipv6_header()
```
