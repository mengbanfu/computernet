#include "Scanner.h"

#include <chrono>
#include <iostream>

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
            std::cout << "[OPEN] ";
            break;
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

    closesocket(sock);
    return result;
}

RangeScanSummary scanPorts(const std::string& ip, const std::vector<int>& ports, int timeoutMs) {
    RangeScanSummary summary{};
    summary.totalPorts = static_cast<int>(ports.size());

    auto startTime = std::chrono::steady_clock::now();

    for (int port : ports) {
        ScanResult portResult = scanPortWithTimeout(ip, port, timeoutMs);

        switch (portResult.status) {
            case PortStatus::Open:
                ++summary.openPorts;
                printPortScanResult(portResult);
                break;
            case PortStatus::Closed:
                ++summary.closedPorts;
                break;
            case PortStatus::Timeout:
                ++summary.timeoutPorts;
                printPortScanResult(portResult);
                break;
        }
    }

    auto endTime = std::chrono::steady_clock::now();
    summary.elapsedSeconds = std::chrono::duration<double>(endTime - startTime).count();

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
