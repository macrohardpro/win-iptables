# winiptables

[English](README.md) | 中文文档

基于 [WinDivert](https://reqrypt.org/windivert.html) 实现的 Windows 版 Linux iptables 移植工具。  
使用你熟悉的 `iptables` 语法，在 Windows 上管理网络流量。

---

## 功能特性

- 兼容 `iptables` 命令行 — `-A`、`-I`、`-D`、`-L`、`-F`、`-Z`、`-N`、`-X`、`-P`、`-E`
- 支持 `filter`、`nat`、`mangle` 三张表及标准内置链
- 匹配条件：`-p`、`-s`、`-d`、`-i`、`-o`、`--sport`、`--dport`、`--tcp-flags`、`--icmp-type`、`-m multiport`、`-m state`
- 目标动作：`ACCEPT`、`DROP`、`REJECT`、`RETURN`、`LOG`、`JUMP`、`MASQUERADE`、`DNAT`、`SNAT`
- 规则持久化（兼容 `iptables-save` / `iptables-restore` 格式）
- 每条规则的数据包/字节计数器（`-L -v`）
- 有状态连接跟踪（`-m state --state NEW,ESTABLISHED,...`）
- 以 Windows 服务方式运行，随系统自动启动
- CLI 通过命名管道与后台服务通信

---

## 架构

```
winiptables.exe（CLI 工具）
    └── 命名管道 ──► winiptables-svc.exe（后台服务）
                            ├── CommandDispatcher → RuleStore
                            ├── TablePipeline（raw→mangle→nat→filter）
                            ├── RuleEngine
                            └── PacketCapture（WinDivert）
```

---

## 环境要求

- Windows 10 / Server 2016 及以上（x64）
- 管理员权限（WinDivert 需要加载内核驱动）
- Visual Studio 2022 / 2026，安装"使用 C++ 的桌面开发"工作负载
- CMake ≥ 3.20

所有第三方依赖（`WinDivert`、`GoogleTest`）已内置于 `third_party/` 目录，无需联网即可编译。

---

## 快速开始

### 1. 编译

```powershell
# CMake 配置
cmake -S . -B build -G "Visual Studio 18 2026" -A x64

# 编译 Release
cmake --build build --config Release
```

也可以使用打包脚本，一键完成编译和打包：

```powershell
.\package.ps1
```

### 2. 安装服务

> 以下所有命令需要在**管理员权限**的 PowerShell 中执行。

```powershell
# 安装并注册 Windows 服务
.\build\bin\Release\winiptables-svc.exe install

# 启动服务
.\build\bin\Release\winiptables.exe service start
```

### 3. 添加规则

```powershell
# 允许入站 TCP 80 端口
winiptables.exe -A INPUT -p tcp --dport 80 -j ACCEPT

# 允许入站 TCP 443 端口
winiptables.exe -A INPUT -p tcp --dport 443 -j ACCEPT

# 拒绝其他所有入站流量
winiptables.exe -P INPUT DROP

# 查看规则列表
winiptables.exe -L -n -v
```

### 4. 保存与恢复规则

```powershell
# 将当前规则集保存到文件
winiptables.exe save > rules.v4

# 从文件恢复规则（重启后或清空后使用）
winiptables.exe restore < rules.v4
```

### 5. 停止并卸载

```powershell
winiptables.exe service stop
winiptables-svc.exe uninstall
```

---

## 控制台模式（调试用）

无需安装服务，直接在终端运行数据包过滤器，适合测试和调试：

```powershell
# 需要管理员权限
.\build\bin\Debug\winiptables-svc.exe --console
```

按 `Ctrl+C` 停止。

---

## 打包部署

使用 `package.ps1` 将可执行文件、WinDivert 运行时和 MSVC CRT 打包到独立目录，可直接部署到干净机器（无需安装 VS 或任何运行时）：

```powershell
.\package.ps1                  # 编译 Release 并打包
.\package.ps1 -Config Debug    # 编译 Debug 并打包
.\package.ps1 -NoBuild         # 跳过编译，直接打包已有产物
.\package.ps1 -WithTests       # 同时打包测试二进制
```

输出目录为 `dist\winiptables\`，将整个目录复制到目标机器后按[快速开始](#快速开始)操作即可。

---

## 运行测试

```powershell
# 编译并运行所有单元测试（Debug）
.\run-tests.ps1

# Release 构建
.\run-tests.ps1 -Config Release

# 跳过编译，直接运行已有测试二进制
.\run-tests.ps1 -NoBuild

# 按套件名过滤
.\run-tests.ps1 -Filter "test_rule*"
```

XML 测试报告输出到 `test-results/` 目录。

---

## 目录结构

```
winiptables/
├── include/winiptables/    # 公共头文件（数据模型、接口、组件声明）
├── src/
│   ├── core/               # 共享静态库（规则引擎、数据包捕获等）
│   ├── cli/                # CLI 可执行文件（winiptables.exe）
│   └── service/            # 服务可执行文件（winiptables-svc.exe）
├── tests/                  # GoogleTest 单元测试
├── third_party/            # 内置依赖（WinDivert、GoogleTest）
├── cmake/                  # CMake 查找模块
├── BUILD.md                # 详细编译说明
├── package.ps1             # 编译 + 打包脚本
└── run-tests.ps1           # 编译 + 测试脚本
```

详细的编译、测试和部署说明请参阅 [BUILD.md](BUILD.md)。

---

## 许可证

MIT
