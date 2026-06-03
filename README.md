# Just — ARM64 安卓用户态调试器（PC 客户端 + 设备端服务端）

面向 **已 Root** 的 Android **arm64** 设备，通过 ADB 部署原生调试服务端，在 Windows 上提供图形化调试界面，支持附加进程、断点、单步、反汇编、内存/寄存器查看与修改等能力（该功能尚未经过全面测试，建议您在使用前自行验证）

---

## 一、功能简介

### 架构

```
┌─────────────────┐     adb forward      ┌──────────────────────────┐
│  client.py      │  tcp:31337 ◄──────►  │  Just_server_arm64       │
│  (PC / Qt GUI)  │                      │  (设备 / ptrace 调试引擎) │
└─────────────────┘                      └───────────┬──────────────┘
                                                     │ ptrace
                                                     ▼
                                          ┌──────────────────────────┐
                                          │  被调试 App / 进程        │
                                          └──────────────────────────┘
```

- **PC 端**：`client.py` 负责设备连接、服务端推送与启动、端口转发、协议解析与界面展示。
- **设备端**：`Just_server_arm64` 基于 `ptrace` 实现附加、断点、单步、内存读写、反汇编（可选 Capstone）等。

### 核心能力

| 类别 | 说明 |
|------|------|
| 进程附加 | 列表选择 PID，发送 `attach <pid>`，断下后刷新反汇编/寄存器/栈/调用栈 |
| 执行控制 | 继续 `r`、步入 `c`、步过 `n`、暂停、结束进程、Trace 追踪 |
| 软件断点 | 指令替换（`brk`），反汇编窗口右键或断点表管理 |
| 硬件断点 | 执行 `bhx`（最多 6）、读/写/读写 `bhr/bhw/bha`（合计最多 4） |
| 内存断点 | 执行/读/写/读写 `bmx/bmr/bmw/bma`，页保护 + 关联表，界面等服务端回执后入表 |
| 反汇编 | `u` / `upkt` 分片；支持修改汇编 `asm`；Capstone 可用时指令更完整 |
| 内存窗口 | `db/dw/dd/dq` 多种宽度；ASCII/UTF-8；右键改内存 `wm`、设断点 |
| 模块 / 线程 | `ml` / `tl`；模块 Tab 可搜索；支持 Dump 当前模块到 PC |
| 日志 / 断点 / Trace | 分 Tab 查看会话日志、断点列表、Trace 输出 |

### 部署路径说明（重要）

因 `/sdcard/Download` 挂载为 **noexec**，二进制无法在该目录直接执行：

1. `adb push` 到 **`/sdcard/Download/Just_server_arm64`**（便于在文件管理器中查看）
2. `su` 复制到 **`/data/local/tmp/Just_server_arm64`** 并 `chmod`
3. 使用 **`su -c nohup`** 在 tmp 路径启动，日志：`/data/local/tmp/Just_server_arm64.log`

---

## 二、环境与依赖

| 项目 | 要求 |
|------|------|
| PC 系统 | Windows（脚本为 `.bat`） |
| Python | 3.x + **PySide6** 或 **PyQt6** |
| ADB | 已加入 PATH，USB 调试已开启 |
| 手机 | **arm64**、**Root**（`su` 可用）、建议 `ro.debuggable=1` |
| 编译服务端 | Android NDK（`aarch64-linux-android` clang），见 `build.bat` |

---

## 三、使用说明

### 1. 编译设备端服务端

```bat
build.bat
```

成功后在项目目录生成 **`Just_server_arm64`**。需设置 `ANDROID_NDK_HOME` 或安装默认路径下的 NDK。

### 2. 启动 PC 调试器

```bat
python client.py
```

**首次连接设备**（需 Root）时，客户端会自动：

- 检测序列号、架构、SDK、SELinux 等
- `adb push` 服务端到 `/sdcard/Download/`
- `su` 安装到 `/data/local/tmp/` 并后台启动
- `adb forward tcp:31337 tcp:31337` 并建立 Socket 会话

也可通过菜单手动操作：

- **设备 → 连接设备**
- **部署 → 一键部署并运行** / **停止**
- **进程 → 附加进程...**

### 3. 附加目标进程

1. 在目标 App 中运行到待调试逻辑（或先用 `test.bat` 启动演示进程）。
2. 菜单 **进程 → 附加进程...**，选择 PID，点 **附加**。
3. 收到 `ATTACH_OK` 后，反汇编、寄存器、栈等窗口会更新；底部命令框可输入服务端命令（如 `help`）。

### 4. 常用界面操作

| 操作 | 方式 |
|------|------|
| 单步步入 / 步过 | 工具栏 **↓** / **↷**，或命令 `c` / `n` |
| 继续运行 | 工具栏 **▶**，或 `r` |
| 暂停 | 工具栏 **⏸** |
| 转到地址 | 反汇编区 **Ctrl+G** |
| 设断点 | 反汇编/内存窗口 **右键菜单** |
| 发送命令 | 底部输入框 + **发送** |
| 查看模块/线程 | 切换到 **模块** / **线程** Tab（自动刷新） |
| Dump 模块 | 工具栏 **D** |

### 5. 命令行参考（底部输入框）

与 `server.cpp` 中 `help` 一致，常用示例：

```text
attach 12345          # 附加（一般由界面完成）
c / n / r             # 步入 / 步过 / 继续
bhx 0x7abc001234      # 硬件执行断点
brk 0x7abc001234      # 软件执行断点
bmx 0x7abc001234      # 内存执行断点
u 0x7abc001000 32     # 反汇编 32 行
dd 0x7abc001000 16    # 按 4 字节查看内存
wm 0x7abc001000 0x1 4 # 写 4 字节内存
asm 0x7abc001000 "nop" # 补丁指令
ml / tl               # 模块列表 / 线程列表
help                  # 帮助
```

### 6. 运行演示进程（test.bat）

用于本地验证 ADB、Root、`su` 执行链：

1. 将编译好的 **`test`**（arm64 可执行文件）放到手机 **`/sdcard/Download/test`**
2. 在项目目录执行：

```bat
test.bat          :: 一直运行，Ctrl+C 结束
test.bat 10       :: 最多运行 10 秒（超时退出码 124）
```

脚本会：`su` 复制到 `/data/local/tmp/test`，再通过 `adb shell -tt su -c` 运行（与 `/sdcard` 的 noexec 限制一致）。

---

## 四、文件作用

| 文件 | 作用 |
|------|------|
| **`client.py`** | PC 端主程序：Qt 界面、ADB 封装、服务端部署/启动、31337 会话、协议解析、断点/内存/反汇编/寄存器/栈/模块/线程等视图与菜单逻辑 |
| **`server.cpp`** | 设备端调试引擎源码：`ptrace` 附加、硬件/软件/内存断点、单步、内存读写、反汇编、TCP 31337 或 `attach pid` 命令行模式 |
| **`Just_server_arm64`** | `server.cpp` 的 arm64 静态链接产物（`build.bat` 生成，需 push 到手机） |
| **`build.bat`** | 使用 NDK `aarch64-linux-android*-clang++` 编译 `server.cpp` → `Just_server_arm64` |
| **`test.bat`** | 在已连接设备上，从 `/sdcard/Download/test` 安装并运行演示进程（不编译 test 本身） |
| **`test`** | （需自行编译，不在仓库）演示用 arm64 二进制，放在手机 `/sdcard/Download/test` |
| **`README.md`** | 本说明文档 |

### `client.py` 主要模块（阅读代码时）

| 类 / 区域 | 作用 |
|-----------|------|
| `Adb` | adb / shell / push / chmod / root 检查 / 进程列表等 |
| `Session` | `adb forward` + 本机 `127.0.0.1:31337` Socket 收发 |
| `MainWindow` | 主界面、菜单、工具栏、Tab、与服务端文本协议解析 |
| `_deploy_server` / `_start_server_process` | 推送到 Download → 安装 tmp → `su` 启动 |
| `_ensure_server_ready_on_startup` | 连设备后自动部署并连接 |
| `_attach_process` | 选择 PID 并 `attach` |
| `_apply_breakpoint_cmd` 等 | 断点命令与界面表同步 |

---

## 五、常见问题

| 现象 | 可能原因 |
|------|----------|
| `test.bat` / 服务端 **Permission denied (126)** | 在 `/sdcard/Download` 直接执行；应走 tmp + `su`（客户端已处理服务端） |
| **启动服务端失败** | 未 Root、`Just_server_arm64` 未编译、push/安装失败；查看日志 Tab 中 `adb push` / `install server to tmp` 的 rc |
| **连接服务端失败** | 31337 被占用、forward 失败、服务端未监听；`adb forward --list` 检查 |
| **附加失败** | PID 不存在、SELinux/ptrace 限制、目标不可调试 |
| **install … Text file busy** | 旧进程仍占用 tmp 下同名文件；客户端/脚本会先 `rm -f` 再复制 |

---

## 六、仓库信息

- 项目名：**arm64-debug-for-pc**
- 窗口标题：**Just_client**（公众号：零基础学逆向）
<img width="258" height="258" alt="qrcode_for_gh_33543c91b3c5_258" src="https://github.com/user-attachments/assets/ce533a51-999a-4585-9f60-83f7c8c30782" />

