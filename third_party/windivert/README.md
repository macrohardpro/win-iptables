# WinDivert 第三方依赖

本目录用于存放 WinDivert 的头文件和预编译库文件。

## 获取方式

从 [WinDivert 官方发布页](https://github.com/basil00/WinDivert/releases) 下载最新版本（建议 2.2.x），
解压后将以下文件复制到对应目录：

```
third_party/windivert/
├── include/
│   └── windivert.h          # WinDivert 主头文件
├── lib/
│   ├── x64/
│   │   ├── WinDivert.lib    # 64 位导入库
│   │   └── WinDivert.dll    # 64 位动态库（运行时需要）
│   └── x86/
│       ├── WinDivert.lib    # 32 位导入库
│       └── WinDivert.dll    # 32 位动态库（运行时需要）
└── README.md                # 本文件
```

## 注意事项

- WinDivert 驱动（`WinDivert64.sys` / `WinDivert32.sys`）需要与 DLL 放在同一目录，
  或安装到系统驱动目录。
- 运行 winiptables-svc 需要管理员权限（WinDivert 驱动加载需要）。
- WinDivert 采用 LGPL-3.0 许可证，商业使用请参阅官方授权说明。

## 替代方式：通过 CMake 指定路径

如果 WinDivert 安装在其他位置，可在 CMake 配置时指定：

```
cmake -DWINDIVERT_ROOT=C:/path/to/windivert ..
```
