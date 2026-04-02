# winiptables 编译指南

## 一、第三方依赖

所有第三方依赖均已放置在 `third_party/` 目录，**无需额外下载**。

| 依赖 | 路径 | 用途 |
|------|------|------|
| **WinDivert** | `third_party/windivert/` | 用户态数据包捕获与注入，过滤功能的底层驱动 |
| **Google Test** | `third_party/googletest/` | 单元测试框架 |
| **ws2_32** | Windows SDK（VS 自带） | Windows 网络套接字库 |
| **advapi32** | Windows SDK（VS 自带） | Windows 服务控制管理器（SCM）API |

> **注意**：WinDivert 运行时需要将 `WinDivert.dll` 和 `WinDivert64.sys` 放在可执行文件同目录，且必须以**管理员权限**运行。

---

## 二、编译前提条件

- **Visual Studio 2026**（安装 **"使用 C++ 的桌面开发"** 工作负载）
- **CMake ≥ 3.20**（VS 自带或从 https://cmake.org 单独安装）

---

## 三、编译步骤

### 1. 进入项目目录

```powershell
cd d:\Work\test-projects\win-iptables\winiptables
```

### 2. CMake 配置（生成 VS 解决方案）

```powershell
# 不含测试（默认，推荐用于发布构建）
cmake -S . -B build -G "Visual Studio 18 2026" -A x64

# 含单元测试
cmake -S . -B build -G "Visual Studio 18 2026" -A x64 -DBUILD_TESTS=ON
```

### 3. 编译 Debug

```powershell
cmake --build build --config Debug
```

只编译特定目标：

```powershell
cmake --build build --config Debug --target winiptables-core
cmake --build build --config Debug --target winiptables
cmake --build build --config Debug --target winiptables-svc
```

### 4. 编译 Release

```powershell
cmake --build build --config Release
```

### 5. 运行测试

> 需要先用 `-DBUILD_TESTS=ON` 配置并编译。

```powershell
cd build
ctest -C Debug --output-on-failure
```

单独运行某个测试：

```powershell
.\build\bin\Debug\test_rule_engine.exe
.\build\bin\Debug\test_persist.exe
.\build\bin\Debug\test_matches.exe
.\build\bin\Debug\test_rule_store.exe
.\build\bin\Debug\test_packet_parse.exe
.\build\bin\Debug\test_parser.exe
```

---

## 三-B、一键编译并运行测试

使用 `run-tests.ps1` 脚本自动完成编译 + 运行 + 汇总报告：

```powershell
# 编译 Debug 并运行所有测试（默认）
.\run-tests.ps1

# 编译 Release 并运行
.\run-tests.ps1 -Config Release

# 跳过编译，直接运行已有测试二进制
.\run-tests.ps1 -NoBuild

# 只运行名称匹配的测试套件（支持通配符）
.\run-tests.ps1 -Filter "test_rule*"

# 自定义 XML 报告输出目录
.\run-tests.ps1 -OutputDir my-reports
```

脚本会：
- 自动以 `-DBUILD_TESTS=ON` 配置并编译
- 逐个运行所有 `test_*.exe`，输出彩色 GTest 日志
- 将每个套件的结果写入 `test-results/<suite>.xml`
- 最终打印汇总（Passed / Failed / Skipped）
- 有失败时以非零退出码退出（适合 CI 集成）

---

## 四、输出产物

编译完成后，所有产物统一输出到 `build/bin/Debug/`（Release 同理）：

```
build/bin/Debug/
├── winiptables.exe        # CLI 工具
├── winiptables-svc.exe    # 后台 Windows 服务
├── winiptables-core.lib   # 核心静态库
├── test_rule_engine.exe   # 仅 -DBUILD_TESTS=ON 时生成
├── test_persist.exe
├── test_matches.exe
├── test_rule_store.exe
├── test_packet_parse.exe
├── test_model.exe
└── test_parser.exe
```

---

## 五、部署运行时文件

编译完成后，将 WinDivert 运行时复制到输出目录：

```powershell
Copy-Item third_party\windivert\lib\x64\WinDivert.dll    build\bin\Debug\
Copy-Item third_party\windivert\lib\x64\WinDivert64.sys  build\bin\Debug\
```

---

## 六、安装并启动服务

> 以下命令需要在**管理员权限**的 PowerShell 中执行。

```powershell
# 安装 Windows 服务
.\build\bin\Debug\winiptables-svc.exe install

# 启动服务
.\build\bin\Debug\winiptables.exe service start

# 验证（列出当前规则）
.\build\bin\Debug\winiptables.exe -L

# 停止服务
.\build\bin\Debug\winiptables.exe service stop

# 卸载服务
.\build\bin\Debug\winiptables-svc.exe uninstall
```

---

## 七、控制台模式（调试用）

不安装服务，直接以控制台模式运行（Ctrl+C 停止）：

```powershell
# 需要管理员权限（WinDivert 要求）
.\build\bin\Debug\winiptables-svc.exe --console
```

---

## 八、打包发行版

使用 `package.ps1` 脚本将编译产物、WinDivert 运行时、MSVC CRT 打包到独立目录，可直接部署到干净机器（无需安装 VS 或任何运行时）：

```powershell
# 编译 Release 并打包（默认行为）
.\package.ps1

# 编译 Debug 并打包
.\package.ps1 -Config Debug

# 自定义输出目录
.\package.ps1 -OutDir my_dist

# 跳过编译，直接打包已有产物
.\package.ps1 -NoBuild

# 跳过编译，打包指定配置的已有产物
.\package.ps1 -Config Debug -NoBuild
```

打包完成后，输出目录 `dist/winiptables/` 包含：

- `winiptables.exe` / `winiptables-svc.exe` — 主程序
- `WinDivert.dll` / `WinDivert64.sys` — WinDivert 运行时
- `vcruntime140*.dll` / `msvcp140*.dll` / `ucrtbase.dll` — MSVC CRT
- `README.txt` — 使用说明

将整个目录复制到目标机器即可使用（需要管理员权限）。
