# SimplePortScanner 跨平台 Socket 改造方案

更新时间：2026-07-07

## 目标

让当前项目同时支持：

- Windows 原生环境：PowerShell / CMD / VS Code Windows 终端 + MSVC 或 MinGW-w64
- WSL / Linux：bash + GCC/Clang + POSIX socket

本次方案只覆盖 TCP Connect 扫描的跨平台改造，不引入 SYN/raw packet 扫描，不要求 root 权限，不改变现有交互式菜单和结果导出行为。

## 当前项目现状

项目现在是一个 Windows 专用 C++17 TCP Connect 端口扫描器。核心问题不是 shell 类型，而是源码直接依赖 Winsock 和 Windows API：

- `main.cpp` 直接包含 `<winsock2.h>`，并调用 `WSAStartup()` / `WSACleanup()`。
- `Scanner.cpp` 使用 `SOCKET`、`INVALID_SOCKET`、`closesocket()`、`ioctlsocket(FIONBIO)`、`WSAGetLastError()`。
- `BannerGrabber.h/.cpp` 暴露 `SOCKET` 类型，并使用 Windows 风格的 socket 超时参数。
- `ConsoleUtil.cpp` 包含 `<windows.h>`，使用 `SetConsoleOutputCP()` / `SetConsoleCP()` 和 `localtime_s()`。
- CMake 已经在 Windows 下链接 `ws2_32`，但源码没有针对 Linux 的条件编译路径。

因此，WSL/Linux 下报错：

```text
fatal error: winsock2.h: No such file or directory
```

是预期结果。

## 参考项目和资料

### Nmap

Nmap 的 TCP Connect Scan 是最贴近本项目的参考模型。Nmap 官方文档说明，connect scan 通过操作系统的 `connect` 系统调用建立连接，不直接构造 raw packet，因此可由非特权用户执行。

参考：

- https://nmap.org/book/scan-methods-connect-scan.html
- https://nmap.org/book/man-port-scanning-techniques.html
- https://github.com/nmap/nmap

可借鉴点：

- 保持 TCP Connect 扫描模型，而不是升级为 raw SYN 扫描。
- 用操作系统 socket API 判断 `open` / `closed` / `filtered or timeout`。
- 跨平台工程中应把平台差异收敛到底层兼容层，而不是散落在扫描业务逻辑里。

### curl

curl 是跨平台网络程序的成熟案例。它将 socket、连接、DNS、超时、错误处理拆成较清晰的内部层，而不是在每个业务分支里直接写平台判断。

参考：

- https://github.com/curl/curl
- https://github.com/curl/curl/blob/master/lib/cf-socket.c
- https://github.com/curl/curl/blob/master/lib/connect.c

可借鉴点：

- socket 连接超时和错误转换应集中处理。
- 业务层只关心“连接成功、连接拒绝、超时、系统错误”，不要直接关心 `errno` 或 `WSAGetLastError()`。

### libuv

libuv 是跨平台异步 I/O 库，Windows 使用 IOCP，Unix 使用 epoll/kqueue/poll 等机制。对本项目来说，引入 libuv 太重，但它的分层方式有参考价值。

参考：

- https://github.com/libuv/libuv
- https://github.com/libuv/libuv/blob/v1.x/src/unix/tcp.c
- https://github.com/libuv/libuv/blob/v1.x/src/win/tcp.c

可借鉴点：

- Unix 和 Windows 的 socket 实现可以分文件或分条件编译维护。
- 对外提供统一函数，内部再选择平台 API。

### masscan

masscan 是高性能端口扫描器，但它以 raw packet/SYN 扫描为核心，和当前项目的 TCP Connect 模型不同。

参考：

- https://github.com/robertdavidgraham/masscan

可借鉴点：

- 不建议本项目跟随 masscan 的 raw packet 方向，因为那会引入权限、抓包、网卡选择和平台驱动问题。
- 本项目应保持教学友好、普通用户可运行的 TCP Connect 扫描路线。

### 平台 API 文档

Windows：

- `WSAStartup()`：https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-wsastartup
- `ioctlsocket()`：https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-ioctlsocket
- `closesocket()`：https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-closesocket

Linux/POSIX：

- `connect(2)`：https://man7.org/linux/man-pages/man2/connect.2.html
- `poll(2)`：https://man7.org/linux/man-pages/man2/poll.2.html
- `select(2)`：https://man7.org/linux/man-pages/man2/select.2.html
- `fcntl(2)`：https://man7.org/linux/man-pages/man2/fcntl.2.html
- `getsockopt(2)`：https://man7.org/linux/man-pages/man2/getsockopt.2.html

关键结论：

- Windows 使用 `WSAStartup()` 初始化 Winsock；Linux 不需要。
- Windows 用 `closesocket()` 关闭 socket；Linux 用 `close()`。
- Windows 用 `ioctlsocket(FIONBIO)` 切换非阻塞；Linux 用 `fcntl(F_GETFL/F_SETFL)` 设置 `O_NONBLOCK`。
- Linux 非阻塞 `connect()` 未立即完成时通常返回 `EINPROGRESS`，之后等待可写，再用 `getsockopt(SO_ERROR)` 判断真实结果。
- Linux `select()` 有 `FD_SETSIZE` 限制；本项目虽然每个线程一次只等一个 socket，但 Linux 路线更推荐用 `poll()`，接口也更直接。

## 推荐总体方案

新增一个轻量跨平台 socket 兼容层，例如：

- `src/NetCompat.h`
- `src/NetCompat.cpp`

业务层不再直接包含 `<winsock2.h>`、`<windows.h>`、`<sys/socket.h>` 等平台头文件。扫描器、Banner 获取器只使用 `NetCompat` 暴露的统一类型和函数。

### 推荐抽象

```cpp
namespace net {

#ifdef _WIN32
using SocketHandle = SOCKET;
#else
using SocketHandle = int;
#endif

bool initialize();
void cleanup();

SocketHandle invalidSocket();
bool isValidSocket(SocketHandle socket);
SocketHandle createTcpSocket();
void closeSocket(SocketHandle socket);

bool setBlocking(SocketHandle socket, bool blocking);
bool setSendReceiveTimeout(SocketHandle socket, int timeoutMs);

int getLastError();
bool isConnectInProgress(int errorCode);

enum class WaitResult {
    Ready,
    Timeout,
    Error
};

WaitResult waitForConnect(SocketHandle socket, int timeoutMs);
bool getSocketError(SocketHandle socket, int& errorCode);

int sendBytes(SocketHandle socket, const char* data, int length);
int recvBytes(SocketHandle socket, char* buffer, int length);

}  // namespace net
```

可以再增加 RAII 类型：

```cpp
class NetworkRuntime {
public:
    NetworkRuntime();
    ~NetworkRuntime();
    bool ok() const;
};

class SocketGuard {
public:
    explicit SocketGuard(net::SocketHandle socket);
    ~SocketGuard();
    net::SocketHandle get() const;
    net::SocketHandle release();
};
```

`NetworkRuntime` 在 Windows 内部调用 `WSAStartup()` / `WSACleanup()`，在 Linux 下是 no-op。`SocketGuard` 避免异常或提前返回时忘记关闭 socket。

## 具体改造点

### 1. `main.cpp`

当前：

- 包含 `<winsock2.h>`
- 手动调用 `WSAStartup()` / `WSACleanup()`

改造后：

- 引入 `NetCompat.h`
- 使用 `net::NetworkRuntime runtime;`
- 如果初始化失败，输出错误并退出
- Linux 下无需任何额外初始化

### 2. `Scanner.cpp`

当前扫描流程可以保留：

1. 创建 TCP socket
2. 设置非阻塞
3. 调用 `connect()`
4. 等待连接完成或超时
5. 用 `SO_ERROR` 判断真实连接结果
6. 开放端口尝试抓 Banner
7. 关闭 socket

跨平台改造只替换底层 API：

| 当前 Windows API | 跨平台替代 |
|---|---|
| `SOCKET` | `net::SocketHandle` |
| `INVALID_SOCKET` | `net::invalidSocket()` |
| `socket()` | `net::createTcpSocket()` |
| `ioctlsocket(FIONBIO)` | `net::setBlocking(socket, false)` |
| `WSAGetLastError()` | `net::getLastError()` |
| `WSAEWOULDBLOCK` | `net::isConnectInProgress(error)` |
| `select()` | `net::waitForConnect()` |
| `getsockopt(SO_ERROR)` | `net::getSocketError()` |
| `closesocket()` | `net::closeSocket()` |

Windows 的 `waitForConnect()` 可以继续用 `select()`；Linux 的 `waitForConnect()` 建议用 `poll()`。

### 3. `BannerGrabber.h/.cpp`

当前 `BannerGrabber.h` 暴露了 Windows 的 `SOCKET`，这是跨平台阻塞点。

改造后：

- 头文件包含 `NetCompat.h`
- 函数签名改为：

```cpp
std::string grabBanner(net::SocketHandle connectedSocket, int port, int timeoutMs = 1000);
```

发送和接收也建议走 `net::sendBytes()` / `net::recvBytes()`。

Linux 下还要注意：

- `SO_RCVTIMEO` / `SO_SNDTIMEO` 参数通常是 `timeval`。
- Windows 下对应参数使用毫秒整数。
- Linux 下 `send()` 可能触发 `SIGPIPE`；建议 `net::sendBytes()` 在 Linux 使用 `MSG_NOSIGNAL`，或在运行期忽略 `SIGPIPE`。更局部、可控的做法是封装 `MSG_NOSIGNAL`。

### 4. `ConsoleUtil.cpp`

当前：

- 使用 `SetConsoleOutputCP(65001)` / `SetConsoleCP(65001)`
- 使用 `localtime_s()`

改造后：

- `setupConsoleUtf8()`：
  - Windows 下保持原逻辑
  - Linux 下 no-op
- `currentDateTimeString()`：
  - Windows 下用 `localtime_s()`
  - Linux 下用 `localtime_r()`

### 5. `CMakeLists.txt`

当前 CMake 已经具备一部分跨平台意识：

```cmake
if(WIN32)
    target_link_libraries(SimplePortScanner PRIVATE ws2_32)
endif()
```

后续需要：

- 把 `src/NetCompat.cpp` 加入 `add_executable`
- Windows 仍链接 `ws2_32`
- Linux 不需要额外 socket 库
- 保留 `Threads::Threads`

可选增强：

```cmake
if(MSVC)
    target_compile_options(SimplePortScanner PRIVATE /utf-8)
else()
    target_compile_options(SimplePortScanner PRIVATE -Wall -Wextra)
endif()
```

## 状态判定规则

保持现有语义：

| 情况 | 状态 |
|---|---|
| `connect()` 立即成功 | `Open` |
| 非阻塞连接等待后 `SO_ERROR == 0` | `Open` |
| 明确连接拒绝，如 `ECONNREFUSED` / `WSAECONNREFUSED` | `Closed` |
| 等待超时，没有明确成功或拒绝 | `Timeout` |
| socket 创建失败、IP 转换失败、其他系统错误 | `Closed` 或内部错误统计，第一阶段保持 `Closed` 兼容现有行为 |

## 不建议的方案

### 直接引入 Boost.Asio

优点是跨平台能力成熟；缺点是引入较大依赖，改变当前项目的教学属性和构建门槛。当前代码规模很小，没必要。

### 直接引入 libuv

libuv 更适合事件循环和大量异步 I/O。当前项目已经通过线程池并发，每个 worker 一次处理一个 socket，使用 libuv 会让架构复杂度明显增加。

### 改成 raw SYN 扫描

raw SYN 扫描性能更好，但需要 root/管理员权限、原始套接字或抓包驱动，并且 Windows/WSL/Linux 差异更大。它不是当前目标。

### 在业务代码中到处写 `#ifdef _WIN32`

短期最快，但长期会让 `Scanner.cpp` 和 `BannerGrabber.cpp` 难读难测。推荐用 `NetCompat` 集中处理平台差异。

## 实施顺序

1. 新增 `NetCompat.h/.cpp`，只实现初始化、关闭、非阻塞、等待连接、错误码转换。
2. 修改 `main.cpp`，用 `NetworkRuntime` 替代直接 Winsock 初始化。
3. 修改 `Scanner.cpp`，让扫描流程走 `net::` 包装函数。
4. 修改 `BannerGrabber.h/.cpp`，去掉对 `SOCKET` 的直接暴露。
5. 修改 `ConsoleUtil.cpp`，对 Windows 控制台和本地时间函数做条件编译。
6. 更新 `CMakeLists.txt`，加入新文件。
7. 分别在 Windows 和 WSL/Linux 编译。
8. 用本机开放端口、关闭端口、超时目标做手工验证。

## 验证命令

### Windows PowerShell

```powershell
cd D:\CnetLab\computernet

cmake -S SimplePortScanner -B SimplePortScanner\cmake-build-windows -G "Visual Studio 17 2022" -A x64
cmake --build SimplePortScanner\cmake-build-windows --config Release

.\SimplePortScanner\cmake-build-windows\Release\SimplePortScanner.exe
```

### WSL/Linux bash

```bash
cd /mnt/d/CnetLab/computernet

cmake -S SimplePortScanner -B SimplePortScanner/cmake-build-linux
cmake --build SimplePortScanner/cmake-build-linux

./SimplePortScanner/cmake-build-linux/SimplePortScanner
```

### 简单手工测试

Linux/WSL 下可以开一个本地 HTTP 服务：

```bash
python3 -m http.server 8080
```

然后扫描：

```text
目标 IP：127.0.0.1
端口：8080,1
超时：500
线程数：10
```

预期：

- `127.0.0.1:8080` 为 `Open`
- `127.0.0.1:1` 通常为 `Closed`

Windows 下也可以用：

```powershell
py -m http.server 8080
```

再用程序扫描 `127.0.0.1:8080,1`。

## 风险和注意事项

- WSL 的 `127.0.0.1` 指向 WSL 环境本身，不一定等同于 Windows 宿主机的 `127.0.0.1`。跨 Windows 宿主机扫描时需要确认目标地址。
- 当前线程数上限是 1000。Linux 下大量线程和 socket 可能受 `ulimit -n` 影响，第一阶段保持现状，后续可考虑更合理的默认线程数或连接池。
- HTTPS 端口 `443` 不会返回明文 HTTP Banner，当前 Banner 抓取只对 `80/8080` 发送 HTTP HEAD。
- Linux 下 `poll()` 等待可写后仍必须读取 `SO_ERROR`，不能仅凭可写判断端口开放。
- `SO_RCVTIMEO` / `SO_SNDTIMEO` 在 Windows 和 Linux 的参数类型不同，必须在兼容层中分别处理。

## 推荐结论

推荐采用“轻量 `NetCompat` 兼容层 + 保留现有 TCP Connect 扫描流程”的方案。

这个方案改动范围可控，不引入第三方依赖，不提高运行权限要求，同时能让项目在 Windows 和 WSL/Linux 下都能编译运行。后续如果要继续扩展 IPv6、CIDR、DNS 主机名、JSON 导出或更高性能扫描，也可以在这个兼容层之上继续演进。
