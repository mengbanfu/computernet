# SimplePortScanner — 端口扫描工具

> 计算机网络课程设计  
> 版本：4.0.2  
> 开发语言：C++17  
> 构建工具：CMake  

---

## 一、项目简介

**SimplePortScanner** 是一款基于 **TCP Connect** 原理实现的端口扫描工具。程序通过 Socket API 对每个目标 `(IP, 端口)` 发起 TCP 连接，根据 `connect()` 的返回结果判断端口状态，并在此基础上逐步扩展了超时控制、多线程并发、表达式解析、服务识别、结果导出、子网主机发现以及 Web 可视化等功能。

本项目**不调用** nmap、masscan、scapy 等现成扫描工具，核心网络逻辑均由 C++ 自行实现，便于理解底层通信过程。

---

## 二、课设目标对应关系

| 课设要求 | 实现情况 |
|----------|----------|
| C++ 实现，Windows 优先 | ✅ 使用 Winsock2（经 `NetCompat` 封装，兼容 Linux/WSL） |
| TCP Connect 扫描 | ✅ `Scanner.cpp` 核心实现 |
| 指定 IP、端口、端口范围 | ✅ `IpParser` + `PortParser` 表达式解析 |
| 连接超时 | ✅ 非阻塞 `connect` + `select`/`poll` |
| 多线程 | ✅ `std::thread` + 任务队列 + `mutex` |
| IP 范围扫描 | ✅ 同 C 段范围 + 子网主机发现 |
| 常见服务识别 | ✅ `ServiceMap`（端口表）+ `ServiceDetector`（协议探测） |
| 结果导出 | ✅ TXT / CSV |
| 命令行程序 | ✅ `CliApp` 菜单式交互 |
| Web 可视化（扩展） | ✅ `--web` 启动内置 HTTP 服务 |

---

## 三、扫描原理

### 3.1 TCP Connect 扫描

Connect 扫描通过操作系统提供的 `connect()` 系统调用，与目标端口完成 TCP 三次握手：

```
客户端                    目标主机
   |  SYN        -------->  |
   |  SYN-ACK    <--------  |   （端口开放）
   |  ACK        -------->  |
   |  连接建立，随后断开
```

| 结果 | 含义 |
|------|------|
| **Open** | `connect()` 在超时内成功，目标有进程在监听 |
| **Closed** | 连接立即失败或被 RST 拒绝 |
| **Timeout** | 超时内无明确响应，可能被防火墙过滤（filtered） |

### 3.2 超时控制

默认阻塞式 `connect()` 对关闭或被过滤的端口可能等待数十秒。本工具将套接字设为非阻塞后发起连接，再通过 `select()`（Windows）或 `poll()`（Linux）等待可写事件，并设置毫秒级超时，避免单个任务长时间阻塞。

### 3.3 多线程模型

扫描任务被拆分为多个 `ScanTask{IP, 端口}`，放入任务队列，由多个工作线程并发取任务并执行 `scanPortWithTimeout()`。任务队列和结果列表通过 `std::mutex` 保护，避免竞态条件。

---

## 四、主要功能

### 4.1 命令行功能（`CliApp`）

启动后显示菜单：

```
SimplePortScanner
1. 开始扫描
2. 查看常见端口列表
3. 查看使用说明
4. 子网主机发现
0. 退出
```

**端口扫描（选项 1）** 支持输入：

- **IP 表达式**：`192.168.1.10`、`192.168.1.1-192.168.1.20`、`192.168.1.1,192.168.1.10`
- **端口表达式**：`80`、`1-1024`、`21,22,80,443`、`21,22,80,1000-1010`
- **超时时间**（毫秒）
- **线程数**
- **是否导出结果**（TXT / CSV）

**子网主机发现（选项 4）**：

- 自动读取本机网卡 `/24` 子网信息（`LocalNetwork`）
- 对子网内主机做 TCP 存活探测（`HostDiscovery`）
- 默认探测端口：80、443、135、445、22

### 4.2 服务识别

| 方式 | 模块 | 说明 |
|------|------|------|
| 端口表猜测 | `ServiceMap` | 基于 IANA 默认端口映射，如 80→HTTP |
| 协议探测 | `ServiceDetector` | 连接成功后发送探测包或读取 Banner |
| Banner 抓取 | `BannerGrabber` | HTTP HEAD 或被动 `recv`（早期扩展） |

识别优先级：**probe > banner > port-guess**

### 4.3 Web 可视化（扩展）

```powershell
SimplePortScanner.exe --web
```

浏览器访问 `http://127.0.0.1:8080`，通过内置 HTTP 服务调用扫描 API。

### 4.4 结果导出

- **CSV**：`IP,Port,Status,Service,Banner,TimeMs,...`
- **TXT**：人类可读格式，默认仅导出开放端口

---

## 五、项目结构

```
SimplePortScanner/
├── README.md                 # 本文件
├── CMakeLists.txt
├── docs/                     # 设计与测试文档
├── web/                      # Web 前端静态资源
└── src/
    ├── main.cpp              # 程序入口（CLI / --web）
    ├── CliApp.cpp            # 命令行菜单与扫描流程
    ├── ConsoleUtil.cpp       # 输入校验、时间格式化
    ├── NetCompat.cpp         # 跨平台 Socket 封装
    ├── Scanner.cpp           # 核心扫描引擎
    ├── PortParser.cpp        # 端口表达式解析
    ├── IpParser.cpp          # IP 表达式解析
    ├── ServiceMap.cpp        # 常见端口服务表
    ├── ServiceDetector.cpp   # 协议探测式服务识别
    ├── BannerGrabber.cpp     # Banner 抓取
    ├── ResultWriter.cpp      # 结果导出
    ├── LocalNetwork.cpp      # 本机子网信息获取
    ├── HostDiscovery.cpp     # 子网主机存活探测
    └── WebApp.cpp            # Web HTTP 服务
```

---

## 六、核心模块说明

| 模块 | 职责 |
|------|------|
| **NetCompat** | 封装 `socket`/`connect`/`select`/`poll`，Windows 与 Linux 统一接口；`NetworkRuntime` 管理 Winsock 初始化 |
| **Scanner** | TCP Connect 扫描、超时判断、多线程任务调度 |
| **PortParser** | 解析端口表达式，去重，过滤非法端口（1–65535） |
| **IpParser** | 解析单 IP、同 C 段范围、逗号分隔多 IP |
| **ServiceDetector** | 对开放端口发 HTTP HEAD、TLS ClientHello、Redis PING 等探测包 |
| **HostDiscovery** | 对子网 IP 列表做存活探测，减少全端口扫描前的无效目标 |
| **ResultWriter** | 将扫描结果写入 TXT/CSV 文件 |

---

## 七、编译与运行

### 7.1 环境要求

- **操作系统**：Windows 10/11（推荐），或 Linux/WSL
- **编译器**：Visual Studio 2022（含 C++ 桌面开发），或 GCC/Clang
- **构建工具**：CMake 3.14+

### 7.2 编译步骤

```powershell
cd SimplePortScanner
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

若提示无法覆盖 exe，先结束旧进程：

```powershell
Get-Process SimplePortScanner -ErrorAction SilentlyContinue | Stop-Process -Force
```

### 7.3 运行方式

**命令行版（答辩推荐）：**

```powershell
cd build\Release
.\SimplePortScanner.exe
```

**Web 版（扩展演示）：**

```powershell
.\SimplePortScanner.exe --web
# 浏览器打开 http://127.0.0.1:8080
```

---

## 八、测试示例

> 以下测试仅针对本机或已授权环境，请勿对未授权主机扫描。

### 8.1 本机端口扫描

```
IP:       127.0.0.1
端口:     80,443,135,8888
超时:     500 ms
线程数:   10
```

可先查看本机监听端口：

```powershell
netstat -an | findstr LISTENING
```

可临时启动测试服务：

```powershell
python -m http.server 8888
```

### 8.2 预期输出示例

```
[OPEN] 127.0.0.1:8888 HTTP-Proxy (SimpleHTTP/0.6) [probe]

扫描摘要
------------------------------------
开始时间：2026-07-09 14:00:01
结束时间：2026-07-09 14:00:03
扫描主机数：1
扫描端口数：4
总任务数：4
开放端口数：1
关闭端口数：3
超时端口数：0
总耗时：1.25 秒
```

### 8.3 子网主机发现

菜单选择 `4`，程序自动列出本机网卡及对应 `/24` 扫描范围，对子网内主机做存活探测。

---

## 九、输出格式说明

| 标签 | 含义 |
|------|------|
| `[OPEN]` | 端口开放 |
| `[CLOSED]` | 端口关闭（范围扫描时不逐条打印，仅统计） |
| `[TIMEOUT]` | 超时无响应（范围扫描时不逐条打印，仅统计） |

开放端口输出格式：

```
[OPEN] IP:端口 服务名 (版本) Banner摘要 [识别方式]
```

识别方式：`probe`（协议探测）、`banner`（Banner 推断）、`port-guess`（端口表猜测）

---

## 十、局限性与说明

1. **Connect 扫描可被日志记录**：完成三次握手，相比 SYN 扫描更容易被目标察觉。
2. **Timeout 不等于 Filtered**：超时仅表示无明确响应，不能严格区分「过滤」与「网络丢包」。
3. **服务识别有误差**：端口可修改、反向代理、TLS 加密等会导致识别结果不准确。
4. **HTTPS 识别受限**：完整 TLS 解析较复杂，当前通过 ClientHello 等方式做轻量探测。
5. **主机发现非 ICMP**：采用 TCP Connect 探测常用端口判断存活，与 ping 原理不同。

---

## 十一、安全与合规声明

本工具仅用于课程设计、实验和教学演示。扫描测试应限于：

- 本机（`127.0.0.1`）
- 虚拟机实验环境
- 局域网中**自己拥有或已获得授权**的主机

**禁止**对未授权目标进行扫描。

---

## 十二、版本演进

| 版本 | 主要变化 |
|------|----------|
| 1.0 | 项目骨架、单端口 TCP Connect 扫描 |
| 1.x | 端口范围、超时控制、表达式解析、多线程 |
| 2.0 | 跨平台 NetCompat、Web 可视化界面 |
| 3.0 | 协议探测服务识别（ServiceDetector）、子网主机发现（HostDiscovery） |

---

## 十三、答辩演示建议

1. 简述 TCP Connect 扫描原理（三次握手、`connect` 判断）
2. 演示命令行菜单扫描 `127.0.0.1`
3. 展示 `[OPEN]` 输出与扫描摘要
4. 说明超时与多线程的必要性
5. 展示 CSV 导出结果
6. 说明服务识别的三层策略及局限性
7. （可选）演示 `--web` 或子网主机发现

---

## 十四、参考资料

- RFC 793 — TCP 协议
- IANA 端口分配列表
- 课程教材：Socket 编程、TCP 三次握手、多线程同步

---

*计算机网络课程设计 — SimplePortScanner*
