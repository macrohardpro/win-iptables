# 实现任务列表

## 任务

- [x] 1. CMake 项目基础搭建
  - [x] 1.1 创建顶层 CMakeLists.txt，配置 C++17 标准、项目名称和子目录
  - [x] 1.2 创建 cmake/FindWinDivert.cmake 查找模块
  - [x] 1.3 创建 third_party/windivert/ 目录并放置 WinDivert 头文件和库文件占位说明
  - [x] 1.4 创建 include/winiptables/ 目录结构（所有头文件占位）
  - [x] 1.5 创建 src/core/CMakeLists.txt、src/cli/CMakeLists.txt、src/service/CMakeLists.txt
  - [x] 1.6 创建 tests/CMakeLists.txt，集成 Google Test 或 Catch2 测试框架

- [x] 2. 核心数据模型
  - [x] 2.1 实现 include/winiptables/model.hpp：定义 TableKind、BuiltinChain、IcmpType、Target、RuleCounters、Rule、Chain、Table
  - [x] 2.2 实现 include/winiptables/imatch.hpp：定义 IMatch 纯虚接口、IMatchExtFactory 纯虚接口、MatchExtRegistry 类
  - [x] 2.3 实现 src/core/model.cpp：MatchExtRegistry 的 register_module 和 parse 方法
  - [x] 2.4 为数据模型编写单元测试（test_model.cpp）

- [x] 3. IPv4/IPv6 数据包解析
  - [x] 3.1 实现 include/winiptables/packet.hpp：定义 Packet 结构体，包含地址族、源/目标 IP、协议、端口、TCP 标志、ICMP 类型、原始数据等字段
  - [x] 3.2 实现 src/core/packet.cpp：parse_ipv4() 和 parse_ipv6() 函数，解析 WinDivert 捕获的原始数据包
  - [x] 3.3 实现 Packet::to_bytes() 序列化方法，支持修改后重新注入
  - [x] 3.4 实现 Packet::is_ipv6() 判断方法
  - [x] 3.5 为数据包解析编写属性测试（test_packet_parse.cpp），验证属性 5（IPv4/IPv6 分类不变量）

- [x] 4. 基础匹配条件实现
  - [x] 4.1 实现 src/core/matches/basic.cpp：ProtocolMatch（-p）、SrcIpMatch（-s）、DstIpMatch（-d）、InIfaceMatch（-i）、OutIfaceMatch（-o），支持 CIDR 网段匹配
  - [x] 4.2 实现 src/core/matches/tcp.cpp：SrcPortMatch（--sport）、DstPortMatch（--dport）、TcpFlagsMatch（--tcp-flags）、IcmpTypeMatch（--icmp-type），支持端口范围
  - [x] 4.3 为所有基础匹配条件实现取反（negated）逻辑（`!` 前缀）
  - [x] 4.4 为匹配条件编写属性测试（test_matches.cpp），验证属性 3（匹配取反对称性）

- [x] 5. 扩展匹配模块（multiport / state）
  - [x] 5.1 实现 src/core/matches/multiport.cpp：MultiportMatch，支持 --sports/--dports 多端口和端口范围列表
  - [x] 5.2 实现 src/core/matches/state.cpp：StateMatch，支持 NEW/ESTABLISHED/RELATED/INVALID 状态匹配（依赖 StatefulTracker）
  - [x] 5.3 在 MatchExtRegistry 中注册 multiport 和 state 模块
  - [x] 5.4 为扩展模块编写单元测试

- [x] 6. RuleStore 线程安全规则存储
  - [x] 6.1 实现 include/winiptables/rule_store.hpp：声明 RuleStore 类，包含所有表/链/规则的 CRUD 接口
  - [x] 6.2 实现 src/core/rule_store.cpp：初始化内置表（filter/nat/mangle）和内置链，使用 std::shared_mutex 保证线程安全
  - [x] 6.3 实现链管理操作：create_chain(-N)、delete_chain(-X)、set_policy(-P)、rename_chain(-E)，包含链名验证（最长 29 字符）
  - [x] 6.4 实现规则管理操作：append_rule(-A)、insert_rule(-I)、delete_rule_by_num(-D)、delete_rule_by_spec(-D)、replace_rule(-R)、list_rules(-L)
  - [x] 6.5 实现计数器操作：zero_counters(-Z)
  - [x] 6.6 为 RuleStore 编写并发单元测试（test_rule_store.cpp）

- [x] 7. RuleEngine 规则评估引擎
  - [x] 7.1 实现 include/winiptables/rule_engine.hpp：声明 RuleEngine 类和 EvalContext 结构体
  - [x] 7.2 实现 src/core/rule_engine.cpp：evaluate() 方法，按链中规则顺序评估，支持 ACCEPT/DROP/RETURN/JUMP 目标
  - [x] 7.3 实现 execute_action()：处理 LOG（写 Windows 事件日志）、REJECT（构造 ICMP 不可达包）、MASQUERADE/DNAT/SNAT（修改数据包地址）
  - [x] 7.4 实现 matches_all()：遍历规则的所有 IMatch 条件，全部匹配才返回 true
  - [x] 7.5 实现规则计数器递增逻辑（原子操作）
  - [x] 7.6 为 RuleEngine 编写属性测试（test_rule_engine.cpp），验证属性 2（规则顺序不变量）和属性 4（计数器单调递增）

- [x] 8. TablePipeline 表处理管道
  - [x] 8.1 实现 include/winiptables/table_pipeline.hpp：声明 TablePipeline 类和 PipelineContext 结构体
  - [x] 8.2 实现 src/core/table_pipeline.cpp：process() 方法，按 raw(预留)→mangle→nat→filter 顺序处理
  - [x] 8.3 实现 eval_table() 私有方法，根据数据包方向（INBOUND/OUTBOUND/FORWARD）选择正确的内置链
  - [ ] 8.4 为 TablePipeline 编写单元测试

- [x] 9. StatefulTracker 连接状态跟踪
  - [x] 9.1 实现 include/winiptables/stateful.hpp：定义 ConnKey、ConnState（NEW/ESTABLISHED/RELATED/INVALID）、ConnEntry 结构体
  - [x] 9.2 实现 src/core/stateful.cpp：StatefulTracker 类，跟踪 TCP 连接状态机（SYN→ESTABLISHED→FIN→CLOSED）
  - [x] 9.3 实现 UDP 会话状态跟踪（基于五元组双向流量）
  - [x] 9.4 实现 LRU 淘汰策略（连接表上限 65536 条）
  - [x] 9.5 实现 TCP 连接超时清理（空闲超时）
  - [ ] 9.6 为 StatefulTracker 编写单元测试

- [x] 10. PacketCapture WinDivert 封装
  - [x] 10.1 实现 include/winiptables/capture.hpp：声明 PacketCapture 类
  - [x] 10.2 实现 src/core/capture.cpp：使用 WinDivertOpen("ip or ipv6", ...) 打开句柄，实现 recv() 阻塞捕获
  - [x] 10.3 实现 inject() 方法，将处理后的数据包重新注入网络栈
  - [x] 10.4 实现错误处理：WinDivert 驱动未安装或权限不足时输出明确错误信息
  - [x] 10.5 实现多线程数据包处理循环（线程池），每个线程独立调用 recv() 并提交到 RuleEngine

- [x] 11. 规则持久化
  - [x] 11.1 实现 include/winiptables/persist.hpp：声明 RulePersist 类
  - [x] 11.2 实现 src/core/persist.cpp：save() 方法，将 RuleStore 序列化为 iptables-save 兼容格式（*table/:chain policy [pkts:bytes]/-A rule/COMMIT）
  - [x] 11.3 实现 load() 方法，解析 iptables-save 格式文件并加载到 RuleStore，遇到语法错误输出行号并中止
  - [x] 11.4 实现 --noflush 模式（追加而非清空）
  - [x] 11.5 实现异步写入（std::async 或后台线程），不阻塞数据包处理
  - [ ] 11.6 为持久化编写属性测试（test_persist.cpp），验证属性 1（规则持久化往返属性）

- [x] 12. CLI 命令行工具
  - [x] 12.1 实现 src/cli/parser.cpp：CommandParser 类，解析 iptables 兼容的 argc/argv，支持 -t/-A/-I/-D/-R/-L/-F/-Z/-N/-X/-P/-E/-n/-v/--line-numbers 等所有参数
  - [x] 12.2 实现 src/cli/ipc_client.cpp：IpcClient 类，通过命名管道 \\.\pipe\winiptables 发送 JSON Lines 请求并接收响应
  - [x] 12.3 实现 src/cli/main.cpp：主入口，解析参数后通过 IpcClient 发送命令，将响应输出到 stdout/stderr，服务未运行时输出错误
  - [x] 12.4 实现服务管理子命令：winiptables service install/start/stop/uninstall
  - [x] 12.5 实现 iptables-save 和 iptables-restore 子命令（通过 IPC 与服务交互）
  - [x] 12.6 为 CommandParser 编写单元测试（test_parser.cpp）

- [x] 13. IPC 命名管道通信
  - [x] 13.1 实现 src/service/ipc_server.cpp：IpcServer 类，创建命名管道服务端，为每个连接创建独立线程
  - [x] 13.2 实现请求解析：从 JSON Lines 中提取 id 和 argv
  - [x] 13.3 实现响应序列化：将 exit_code/stdout/stderr 序列化为 JSON Lines 返回给 CLI
  - [x] 13.4 实现 src/service/command_dispatcher.cpp：CommandDispatcher 类，将解析后的命令路由到 RuleStore 对应操作
  - [ ] 13.5 为 IPC 通信编写集成测试

- [x] 14. Windows 服务实现
  - [x] 14.1 实现 src/service/service.cpp：Windows 服务入口，注册 ServiceMain 和 HandlerEx 回调，处理 START/STOP/PAUSE 控制码
  - [x] 14.2 实现服务启动逻辑：加载持久化规则 → 初始化 RuleStore → 启动 PacketCapture 线程池 → 启动 IpcServer
  - [x] 14.3 实现服务停止逻辑：优雅关闭 PacketCapture → 保存规则到持久化文件 → 关闭 IpcServer
  - [x] 14.4 实现 src/service/main.cpp：根据命令行参数决定以服务模式或控制台模式运行
  - [x] 14.5 实现服务安装/卸载逻辑（调用 Windows SCM API：CreateService/DeleteService）
  - [ ] 14.6 为服务生命周期编写集成测试
