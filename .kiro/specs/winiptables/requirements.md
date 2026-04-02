# 需求文档

## 简介

winiptables 是一款运行在 Windows 平台的网络过滤工具，旨在移植 Linux iptables 的核心功能和命令行接口。
工具基于 WinDivert 技术实现数据包的捕获、过滤与注入，支持 iptables 的表（tables）、链（chains）、规则（rules）和目标（targets）等核心概念，
使熟悉 Linux iptables 的用户能够在 Windows 环境下以相同的方式管理网络流量。

## 词汇表

- **winiptables**：本工具的名称，Windows 平台的 iptables 移植实现
- **WinDivert**：Windows 平台的用户态数据包捕获与注入库，winiptables 的底层驱动技术
- **Table（表）**：规则的逻辑分组，包括 filter、nat、mangle 等
- **Chain（链）**：表中的规则序列，包括内置链（INPUT、OUTPUT、FORWARD 等）和用户自定义链
- **Rule（规则）**：链中的一条匹配+目标条目，决定匹配数据包的处理方式
- **Target（目标）**：规则匹配后的动作，如 ACCEPT、DROP、REJECT、RETURN、MASQUERADE 等
- **Match（匹配条件）**：用于筛选数据包的条件，如源/目标 IP、端口、协议等
- **Policy（默认策略）**：链中无规则匹配时的默认处理动作
- **RuleEngine（规则引擎）**：负责按顺序评估链中规则并执行目标动作的核心组件
- **PacketCapture（数据包捕获器）**：基于 WinDivert 实现数据包捕获与注入的组件
- **CLI（命令行接口）**：winiptables 提供的命令行工具，兼容 iptables 命令语法
- **Ruleset（规则集）**：当前所有表和链的完整规则配置
- **Stateful_Tracker（状态跟踪器）**：跟踪 TCP/UDP 连接状态的组件，支持 conntrack 匹配

---

## 需求

### 需求 1：命令行接口兼容性

**用户故事：** 作为熟悉 Linux iptables 的网络管理员，我希望使用与 iptables 一致的命令行语法，以便无需重新学习即可在 Windows 上管理网络规则。

#### 验收标准

1. THE CLI SHALL 支持 `-t <table>` 参数指定操作的目标表，默认表为 `filter`
2. THE CLI SHALL 支持以下命令动词：`-A`（追加规则）、`-I`（插入规则）、`-D`（删除规则）、`-R`（替换规则）、`-L`（列出规则）、`-F`（清空链）、`-Z`（清零计数器）、`-N`（新建链）、`-X`（删除链）、`-P`（设置默认策略）、`-E`（重命名链）
3. THE CLI SHALL 支持 `-n` 参数以数字形式显示 IP 地址和端口，不进行 DNS 反向解析
4. THE CLI SHALL 支持 `--line-numbers` 参数在列出规则时显示规则编号
5. THE CLI SHALL 支持 `-v` 参数显示详细信息，包括数据包计数和字节计数
6. IF 用户输入的命令语法不合法，THEN THE CLI SHALL 输出与 iptables 格式一致的错误信息并返回非零退出码
7. THE CLI SHALL 支持 `iptables-save` 和 `iptables-restore` 兼容的规则导出与导入格式

---

### 需求 2：表（Table）管理

**用户故事：** 作为网络管理员，我希望工具支持 iptables 的多张表，以便按功能分类管理不同类型的网络规则。

#### 验收标准

1. THE winiptables SHALL 内置支持 `filter` 表，包含 INPUT、OUTPUT、FORWARD 三条内置链
2. THE winiptables SHALL 内置支持 `nat` 表，包含 PREROUTING、OUTPUT、POSTROUTING 三条内置链
3. THE winiptables SHALL 内置支持 `mangle` 表，包含 PREROUTING、INPUT、FORWARD、OUTPUT、POSTROUTING 五条内置链
4. WHEN 用户指定不存在的表名，THE CLI SHALL 返回错误信息 `iptables: can't initialize iptables table '<name>': Table does not exist`
5. THE winiptables SHALL 按照 `raw → mangle → nat → filter` 的顺序处理各表中的规则
6. THE winiptables 的表处理管道 SHALL 在 `mangle` 表之前预留 `raw` 表的处理位置，以便后续版本扩展支持 `raw` 表（当前版本不实现 raw 表功能，但架构上须保留该扩展点）

---

### 需求 3：链（Chain）管理

**用户故事：** 作为网络管理员，我希望能够创建、删除和管理规则链，以便灵活组织网络过滤逻辑。

#### 验收标准

1. WHEN 用户执行 `-N <chain>` 命令，THE winiptables SHALL 在指定表中创建同名的用户自定义链
2. IF 用户执行 `-N <chain>` 时链名已存在，THEN THE winiptables SHALL 返回错误 `Chain already exists`
3. WHEN 用户执行 `-X <chain>` 命令，THE winiptables SHALL 删除指定的用户自定义链
4. IF 用户执行 `-X <chain>` 时链非空或被其他规则引用，THEN THE winiptables SHALL 拒绝删除并返回相应错误信息
5. WHEN 用户执行 `-P <chain> <target>` 命令，THE winiptables SHALL 将内置链的默认策略设置为指定目标
6. IF 用户尝试对用户自定义链设置默认策略，THEN THE winiptables SHALL 返回错误信息
7. THE winiptables SHALL 支持链名最长 29 个字符，且仅包含字母、数字、连字符和下划线

---

### 需求 4：规则（Rule）管理

**用户故事：** 作为网络管理员，我希望能够添加、删除、插入和列出规则，以便精确控制网络流量的处理方式。

#### 验收标准

1. WHEN 用户执行 `-A <chain> <rule>` 命令，THE RuleEngine SHALL 将规则追加到指定链的末尾
2. WHEN 用户执行 `-I <chain> [rulenum] <rule>` 命令，THE RuleEngine SHALL 将规则插入到指定位置，默认插入到第 1 条
3. WHEN 用户执行 `-D <chain> <rulenum>` 命令，THE RuleEngine SHALL 删除指定编号的规则
4. WHEN 用户执行 `-D <chain> <rule>` 命令，THE RuleEngine SHALL 删除与指定规则完全匹配的第一条规则
5. IF 用户执行 `-D` 时指定的规则不存在，THEN THE RuleEngine SHALL 返回错误 `Bad rule (does not exist)`
6. WHEN 用户执行 `-R <chain> <rulenum> <rule>` 命令，THE RuleEngine SHALL 用新规则替换指定编号的规则
7. WHEN 用户执行 `-L [chain]` 命令，THE CLI SHALL 按顺序列出指定链（或所有链）的规则
8. THE RuleEngine SHALL 按规则在链中的顺序依次评估，遇到第一条匹配规则后执行其目标动作

---

### 需求 5：匹配条件（Match）支持

**用户故事：** 作为网络管理员，我希望工具支持丰富的数据包匹配条件，以便精确筛选需要处理的网络流量。

#### 验收标准

1. THE RuleEngine SHALL 支持 `-p <protocol>` 匹配协议，支持 `tcp`、`udp`、`icmp`、`all`
2. THE RuleEngine SHALL 支持 `-s <source>` 匹配源 IP 地址或 CIDR 网段
3. THE RuleEngine SHALL 支持 `-d <destination>` 匹配目标 IP 地址或 CIDR 网段
4. THE RuleEngine SHALL 支持 `-i <interface>` 匹配入站网络接口名称
5. THE RuleEngine SHALL 支持 `-o <interface>` 匹配出站网络接口名称
6. WHEN 协议为 TCP 或 UDP 时，THE RuleEngine SHALL 支持 `--sport <port>` 和 `--dport <port>` 匹配源端口和目标端口，支持端口范围格式 `<start>:<end>`
7. WHEN 协议为 TCP 时，THE RuleEngine SHALL 支持 `--tcp-flags <mask> <comp>` 匹配 TCP 标志位
8. WHEN 协议为 ICMP 时，THE RuleEngine SHALL 支持 `--icmp-type <type>` 匹配 ICMP 类型
9. THE RuleEngine SHALL 支持在任意匹配条件前加 `!` 表示取反
10. THE RuleEngine SHALL 支持 `-m multiport` 扩展模块，允许在单条规则中指定多个端口或端口范围
11. THE RuleEngine SHALL 支持 `-m state --state <states>` 匹配连接状态，支持 `NEW`、`ESTABLISHED`、`RELATED`、`INVALID`
12. THE RuleEngine SHALL 采用插件化扩展架构支持 `-m <module>` 扩展匹配模块，当前版本仅内置 `multiport` 和 `state` 模块，架构上须预留标准接口以便后续添加 `limit`、`string`、`iprange` 等扩展模块

---

### 需求 6：目标动作（Target）支持

**用户故事：** 作为网络管理员，我希望工具支持 iptables 的标准目标动作，以便对匹配的数据包执行相应处理。

#### 验收标准

1. WHEN 规则目标为 `ACCEPT`，THE RuleEngine SHALL 允许数据包通过并停止当前链的规则评估
2. WHEN 规则目标为 `DROP`，THE RuleEngine SHALL 静默丢弃数据包并停止当前链的规则评估
3. WHEN 规则目标为 `REJECT`，THE RuleEngine SHALL 丢弃数据包并向发送方发送 ICMP 不可达消息，支持 `--reject-with` 参数指定 ICMP 类型
4. WHEN 规则目标为 `RETURN`，THE RuleEngine SHALL 停止当前链的规则评估并返回调用链
5. WHEN 规则目标为用户自定义链名，THE RuleEngine SHALL 跳转到该链继续评估规则
6. WHEN 规则目标为 `LOG`，THE RuleEngine SHALL 将数据包信息记录到系统日志并继续评估后续规则，支持 `--log-prefix` 和 `--log-level` 参数
7. WHEN 规则目标为 `MASQUERADE`（仅 nat 表 POSTROUTING 链），THE RuleEngine SHALL 对出站数据包执行源地址伪装（SNAT 到出口 IP）
8. WHEN 规则目标为 `DNAT`（仅 nat 表），THE RuleEngine SHALL 修改数据包的目标地址，支持 `--to-destination <ip>[:<port>]` 参数
9. WHEN 规则目标为 `SNAT`（仅 nat 表 POSTROUTING 链），THE RuleEngine SHALL 修改数据包的源地址，支持 `--to-source <ip>[:<port>]` 参数

---

### 需求 7：数据包捕获与注入

**用户故事：** 作为工具的底层实现，PacketCapture 需要可靠地捕获和注入 Windows 网络数据包，以支持上层规则引擎的工作。

#### 验收标准

1. THE PacketCapture SHALL 使用 WinDivert 捕获经过 Windows 网络栈的入站、出站和转发数据包
2. WHEN WinDivert 驱动未安装或权限不足，THE PacketCapture SHALL 输出明确的错误信息并退出，提示用户以管理员权限运行
3. THE PacketCapture SHALL 同时支持捕获 IPv4 和 IPv6 数据包，THE RuleEngine SHALL 对 IPv4 和 IPv6 数据包分别进行规则匹配（对应 iptables 和 ip6tables 功能）
4. THE RuleEngine SHALL 在规则评估完成后，通过 WinDivert 将 ACCEPT 的数据包重新注入网络栈
5. WHEN 数据包被 DROP 或 REJECT，THE PacketCapture SHALL 不重新注入该数据包
6. THE PacketCapture SHALL 在多线程环境下安全地处理并发数据包，不产生竞态条件

---

### 需求 8：规则持久化

**用户故事：** 作为网络管理员，我希望规则能够保存到文件并在系统重启后恢复，以便维护持久的网络过滤策略。

#### 验收标准

1. THE CLI SHALL 支持 `iptables-save` 子命令，将当前 Ruleset 以文本格式输出到标准输出或指定文件
2. THE CLI SHALL 支持 `iptables-restore` 子命令，从标准输入或指定文件读取规则并加载到 RuleEngine
3. WHEN 执行 `iptables-restore` 时遇到语法错误的规则行，THE CLI SHALL 输出包含行号的错误信息并中止加载
4. THE winiptables SHALL 支持 `--noflush` 参数，在 `iptables-restore` 时不清空现有规则而是追加
5. FOR ALL 合法的 Ruleset，执行 `iptables-save` 后再执行 `iptables-restore` SHALL 产生与原始 Ruleset 等价的规则集（往返属性）

---

### 需求 9：规则计数器

**用户故事：** 作为网络管理员，我希望查看每条规则匹配的数据包数量和字节数，以便监控网络流量和调试规则。

#### 验收标准

1. THE RuleEngine SHALL 为每条规则维护匹配数据包计数器和字节计数器
2. WHEN 数据包匹配某条规则，THE RuleEngine SHALL 将该规则的数据包计数器加 1，字节计数器加上数据包大小（字节）
3. WHEN 用户执行 `-Z [chain]` 命令，THE RuleEngine SHALL 将指定链（或所有链）的所有规则计数器清零
4. WHEN 用户执行 `-L -v` 命令，THE CLI SHALL 在规则列表中显示每条规则的数据包计数和字节计数

---

### 需求 10：连接状态跟踪

**用户故事：** 作为网络管理员，我希望工具支持连接状态跟踪，以便编写有状态的防火墙规则（如只允许已建立的连接通过）。

#### 验收标准

1. THE Stateful_Tracker SHALL 跟踪 TCP 连接的状态，识别 NEW、ESTABLISHED、RELATED、INVALID 四种状态
2. THE Stateful_Tracker SHALL 跟踪 UDP 会话状态，基于源/目标 IP 和端口的双向流量识别 ESTABLISHED 状态
3. WHEN TCP 连接完成四次挥手或超过空闲超时时间，THE Stateful_Tracker SHALL 从连接表中移除该连接条目
4. WHEN 连接表条目数量达到上限（默认 65536），THE Stateful_Tracker SHALL 按 LRU 策略淘汰最久未使用的条目
5. THE RuleEngine SHALL 支持 `-m state --state <states>` 语法，基于 Stateful_Tracker 的连接状态匹配数据包


---

### 需求 11：Windows 服务模式与 IPC 通信

**用户故事：** 作为网络管理员，我希望 winiptables 作为 Windows 后台服务持续运行并实时过滤数据包，同时通过 CLI 工具随时管理规则，以便在系统运行期间始终保持网络过滤策略生效。

#### 验收标准

1. THE winiptables SHALL 支持作为 Windows 服务（Windows Service）在后台持续运行，随系统启动自动加载并实时过滤数据包
2. WHEN winiptables 服务启动，THE winiptables SHALL 从持久化存储中加载上次保存的 Ruleset 并初始化 RuleEngine 和 PacketCapture
3. THE CLI SHALL 通过命名管道（Named Pipe）与后台服务进行 IPC 通信，将用户输入的命令和规则发送给服务执行
4. WHEN CLI 向服务发送命令，THE winiptables 服务 SHALL 执行命令并将结果（包括规则列表、错误信息等）通过命名管道返回给 CLI
5. IF 后台服务未运行时 CLI 尝试执行命令，THEN THE CLI SHALL 输出明确的错误信息提示服务未启动，并返回非零退出码
6. THE winiptables SHALL 支持通过 `sc` 命令或 winiptables 专用子命令（如 `winiptables service install/start/stop/uninstall`）管理服务的安装、启动、停止和卸载
7. WHILE 服务运行期间，THE winiptables 服务 SHALL 持续捕获并过滤数据包，不因 CLI 命令的执行而中断数据包处理
8. WHEN 服务接收到规则变更命令，THE winiptables 服务 SHALL 以原子方式更新 RuleEngine 中的规则，确保规则更新期间不丢失数据包
