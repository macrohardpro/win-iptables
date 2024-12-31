# win_iptables
基于 WinDivert 实现的 Windows 版本 iptables

# 蓝图

## README.md
- [English](README.md)

## 技术栈 (Technology Stack)

- **编程语言 (Programming Languages):**
  - C/C++: C++17。
  - Python: 辅助工具。

- **库和框架 (Libraries and Frameworks):**
  - PortBender: 核心网络分组过滤库，用于实现规则匹配和流量控制。
  - Windows API: 用于与操作系统交互，如创建服务、管理进程等。

- **构建工具 (Build Tools):**
  - CMake: 跨平台构建系统生成器，用于配置和编译项目。
  - MSBuild: 使用 Visual Studio 编译项目时的默认构建系统。
  - conan: 跨平台C++包管理工具
  
- **版本控制系统 (Version Control System):**
  - Git: 分布式版本控制系统，用于代码版本管理和协作开发。

- **测试框架 (Testing Frameworks):**
  - Google Test: C++ 的单元测试框架。

- **持续集成/持续部署 (CI/CD):**
  - GitHub Actions: 自动化构建、测试和部署流程。

## 规则管理 (Rule Management)

- [ ] 基本规则操作
  - [ ] 添加规则
  - [ ] 删除规则
  - [ ] 修改现有规则
  
- [ ] 规则链管理
  - [ ] 创建自定义链
  - [ ] 插入规则到指定链
  - [ ] 设置链策略

- [ ] 预定义规则集
  - [ ] 允许所有流量
  - [ ] 拒绝所有流量
  - [ ] 常见安全配置模板

## 日志与监控 (Logging and Monitoring)

- [ ] 实时日志查看
  - [ ] 显示匹配规则的流量日志
  - [ ] 过滤和搜索日志条目

- [ ] 流量统计
  - [ ] 网络连接统计
  - [ ] 数据传输量监测

- [ ] 警报系统
  - [ ] 自定义触发条件
  - [ ] 通知方式（弹窗、邮件等）

## 用户界面 (User Interface)

- [ ] 命令行接口 (CLI)
  - [ ] 支持常用 iptables 命令
  - [ ] 交互式帮助文档

- [ ] 图形用户界面 (GUI)
  - [ ] 可视化规则编辑器
  - [ ] 状态面板和仪表板

## 文档和支持 (Documentation and Support)

- [ ] 在线帮助和教程
  - [ ] 快速入门指南
  - [ ] 详细使用手册

- [ ] 社区论坛和 FAQ
  - [ ] 用户交流平台
  - [ ] 解决常见问题

## 测试与验证 (Testing and Validation)

- [ ] 自动化测试套件
  - [ ] 单元测试
  - [ ] 集成测试

- [ ] 用户反馈循环
  - [ ] Beta 版本发布
  - [ ] 收集改进意见

## 发布与更新 (Release and Updates)

- [ ] 版本控制
  - [ ] 定期更新
  - [ ] 回滚机制

- [ ] 多语言支持
  - [ ] 国际化和本地化