#include "Scanner.h"
#include "BannerGrabber.h"
#include "ServiceMap.h"

#include <chrono>
#include <iostream>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

#include <winsock2.h>
#include <ws2tcpip.h>

bool scanPort(const std::string& ip, int port) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    // AF_INET     - IPv4 地址族
    // SOCK_STREAM - 面向连接的字节流（TCP）
    // IPPROTO_TCP - 使用 TCP 协议
    if (sock == INVALID_SOCKET) {
        return false;
    }

    sockaddr_in targetAddr{};
    targetAddr.sin_family = AF_INET;
    targetAddr.sin_port = htons(static_cast<u_short>(port));

    if (inet_pton(AF_INET, ip.c_str(), &targetAddr.sin_addr) != 1) {
        closesocket(sock);
        return false;
    }

    int result = connect(sock,
                         reinterpret_cast<sockaddr*>(&targetAddr),
                         sizeof(targetAddr));

    closesocket(sock);
    return result == 0;
}

void printPortScanResult(const ScanResult& result) {
    switch (result.status) {
        case PortStatus::Open:
            std::cout << "[OPEN] " << result.ip << ":" << result.port << ' '
                      << getServiceName(result.port);
            if (!result.banner.empty()) {
                std::cout << ' ' << result.banner;
            }
            std::cout << std::endl;
            return;
        case PortStatus::Closed:
            std::cout << "[CLOSED] ";
            break;
        case PortStatus::Timeout:
            std::cout << "[TIMEOUT] ";
            break;
    }
    std::cout << result.ip << ":" << result.port << std::endl;
}

ScanResult scanPortWithTimeout(const std::string& ip, int port, int timeoutMs) {
    ScanResult result{};
    result.ip = ip;
    result.port = port;

    auto startTime = std::chrono::steady_clock::now();

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        result.status = PortStatus::Closed;
        result.timeMs = 0;
        return result;
    }

    // ----------------------------------------------------------------
    // 为什么要设置非阻塞？
    // ----------------------------------------------------------------
    // 默认情况下 connect() 是阻塞的：若目标无响应，会一直等到 TCP 重传超时
    // （Windows 上可能 20~30 秒），扫描大量端口时无法接受。
    //
    // 设为非阻塞后，connect() 会立即返回：
    //   - 若返回 0：已连接成功（本机回环等场景可能瞬间完成）
    //   - 若返回 SOCKET_ERROR 且 errno == WSAEWOULDBLOCK：
    //       连接正在进行中，此时用 select() 等待"可写"或"异常"事件并设超时
    //   - 若返回其他错误（如 WSAECONNREFUSED）：端口关闭，立即判定 Closed
    u_long nonBlocking = 1;
    if (ioctlsocket(sock, FIONBIO, &nonBlocking) != 0) {
        closesocket(sock);
        result.status = PortStatus::Closed;
        auto endTime = std::chrono::steady_clock::now();
        result.timeMs = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
        return result;
    }

    sockaddr_in targetAddr{};
    targetAddr.sin_family = AF_INET;
    targetAddr.sin_port = htons(static_cast<u_short>(port));

    if (inet_pton(AF_INET, ip.c_str(), &targetAddr.sin_addr) != 1) {
        closesocket(sock);
        result.status = PortStatus::Closed;
        auto endTime = std::chrono::steady_clock::now();
        result.timeMs = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
        return result;
    }

    int connectResult = connect(sock,
                                reinterpret_cast<sockaddr*>(&targetAddr),
                                sizeof(targetAddr));

    if (connectResult == 0) {
        // Open：connect 立即成功，目标端口有进程在 listen
        result.status = PortStatus::Open;
    } else {
        int connectError = WSAGetLastError();

        if (connectError == WSAEWOULDBLOCK) {
            // ----------------------------------------------------------------
            // select() 在这里的作用
            // ----------------------------------------------------------------
            // connect 非阻塞启动后，内核在后台继续三次握手。
            // select() 监视 socket 是否变为"可写"（握手完成）或"异常"（握手失败），
            // 并在 timeoutMs 内没有事件时返回 0，从而实现可控的超时等待。
            //
            // writefds：连接成功时 socket 通常变为可写
            // exceptfds：连接失败时可能触发异常集合
            fd_set writeFds;
            fd_set exceptFds;
            FD_ZERO(&writeFds);
            FD_ZERO(&exceptFds);
            FD_SET(sock, &writeFds);
            FD_SET(sock, &exceptFds);

            timeval tv{};
            tv.tv_sec = timeoutMs / 1000;
            tv.tv_usec = (timeoutMs % 1000) * 1000;

            // Windows 上 nfds 参数被忽略，传 0 即可
            int selectResult = select(0, nullptr, &writeFds, &exceptFds, &tv);

            if (selectResult == 0) {
                // Timeout：在 timeoutMs 内没有完成连接，也无明确拒绝
                // 常见于防火墙丢弃 SYN（filtered），而非端口关闭
                result.status = PortStatus::Timeout;
            } else if (selectResult == SOCKET_ERROR) {
                result.status = PortStatus::Closed;
            } else {
                // select 检测到事件，用 SO_ERROR 确认 connect 的真实结果
                if (FD_ISSET(sock, &exceptFds)) {
                    // Closed：收到 RST 等，连接被拒绝
                    result.status = PortStatus::Closed;
                } else if (FD_ISSET(sock, &writeFds)) {
                    int soError = 0;
                    int optLen = sizeof(soError);
                    getsockopt(sock, SOL_SOCKET, SO_ERROR,
                               reinterpret_cast<char*>(&soError), &optLen);

                    if (soError == 0) {
                        // Open：SO_ERROR 为 0 表示三次握手成功
                        result.status = PortStatus::Open;
                    } else {
                        // Closed：如 WSAECONNREFUSED，目标主动拒绝
                        result.status = PortStatus::Closed;
                    }
                } else {
                    result.status = PortStatus::Closed;
                }
            }
        } else {
            // Closed：connect 立即失败（端口未监听、主动拒绝等）
            result.status = PortStatus::Closed;
        }
    }

    auto endTime = std::chrono::steady_clock::now();
    result.timeMs = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();

    // 仅对开放端口尝试 Banner 获取（短超时，不影响 closed/timeout 判定）
    if (result.status == PortStatus::Open) {
        result.banner = grabBanner(sock, port, 1000);
    }

    closesocket(sock);
    return result;
}

RangeScanSummary scanPorts(const std::string& ip, const std::vector<int>& ports, int timeoutMs) {
    return scanTargets({ip}, ports, timeoutMs);
}

RangeScanSummary scanTargets(const std::vector<std::string>& ips,
                             const std::vector<int>& ports,
                             int timeoutMs) {
    return scanTargetsConcurrent(ips, ports, timeoutMs, 1);
}

RangeScanSummary scanTargetsConcurrent(const std::vector<std::string>& ips,
                                       const std::vector<int>& ports,
                                       int timeoutMs,
                                       int threadCount,
                                       std::vector<ScanResult>* openResultsOut) {
    RangeScanSummary summary{};
    summary.hostCount = static_cast<int>(ips.size());
    summary.portCount = static_cast<int>(ports.size());
    summary.totalTasks = summary.hostCount * summary.portCount;

    if (summary.totalTasks == 0) {
        return summary;
    }

    if (threadCount < 1) {
        threadCount = 1;
    }
    if (threadCount > summary.totalTasks) {
        threadCount = summary.totalTasks;
    }

    // ----------------------------------------------------------------
    // 1. 构建任务队列：每个 (IP, 端口) 组合对应一个 ScanTask
    // ----------------------------------------------------------------
    std::queue<ScanTask> taskQueue;
    for (const std::string& ip : ips) {
        for (int port : ports) {
            taskQueue.push(ScanTask{ip, port});
        }
    }

    // 开放端口结果列表（扫描过程中由多线程写入，需 mutex 保护）
    std::vector<ScanResult> openResults;
    openResults.reserve(static_cast<size_t>(summary.totalTasks / 10 + 1));

    std::mutex queueMutex;    // 保护任务队列
    std::mutex resultMutex;   // 保护 openResults
    std::mutex statsMutex;    // 保护 closed / timeout 计数

    // 工作线程函数：不断从队列取任务并扫描
    auto worker = [&]() {
        while (true) {
            ScanTask task;

            // 取任务时必须加锁，避免多个线程同时 pop 同一任务
            {
                std::lock_guard<std::mutex> lock(queueMutex);
                if (taskQueue.empty()) {
                    break;
                }
                task = taskQueue.front();
                taskQueue.pop();
            }

            ScanResult portResult = scanPortWithTimeout(task.ip, task.port, timeoutMs);

            if (portResult.status == PortStatus::Open) {
                {
                    std::lock_guard<std::mutex> lock(resultMutex);
                    openResults.push_back(portResult);
                }
                {
                    std::lock_guard<std::mutex> lock(statsMutex);
                    ++summary.openPorts;
                }
            } else if (portResult.status == PortStatus::Closed) {
                std::lock_guard<std::mutex> lock(statsMutex);
                ++summary.closedPorts;
            } else {
                std::lock_guard<std::mutex> lock(statsMutex);
                ++summary.timeoutPorts;
            }
        }
    };

    const auto startTime = std::chrono::steady_clock::now();

    // ----------------------------------------------------------------
    // 2. 启动多个工作线程并发扫描
    // ----------------------------------------------------------------
    std::vector<std::thread> workers;
    workers.reserve(static_cast<size_t>(threadCount));
    for (int i = 0; i < threadCount; ++i) {
        workers.emplace_back(worker);
    }

    for (std::thread& t : workers) {
        t.join();
    }

    const auto endTime = std::chrono::steady_clock::now();
    summary.elapsedSeconds = std::chrono::duration<double>(endTime - startTime).count();

    // 全部完成后统一打印开放端口，避免多线程同时写 cout 导致输出混乱
    for (const ScanResult& result : openResults) {
        printPortScanResult(result);
    }

    if (openResultsOut != nullptr) {
        *openResultsOut = std::move(openResults);
    }

    return summary;
}

RangeScanSummary scanPortRange(const std::string& ip, int startPort, int endPort, int timeoutMs) {
    std::vector<int> ports;
    ports.reserve(static_cast<size_t>(endPort - startPort + 1));
    for (int port = startPort; port <= endPort; ++port) {
        ports.push_back(port);
    }
    return scanPorts(ip, ports, timeoutMs);
}
