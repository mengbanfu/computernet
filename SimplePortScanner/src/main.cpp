/**
 * SimplePortScanner - 第一版 TCP Connect 端口扫描
 *
 * 扫描原理：
 *   对每个目标端口发起完整的 TCP 三次握手（Connect 扫描）。
 *   connect() 成功 → 目标端口有进程在监听，视为开放。
 *   connect() 失败 → 端口关闭或被拒绝。
 */

#include <iostream>
#include <string>

// Winsock2 头文件必须在 windows.h 之前包含（若用到 windows.h）
#include <winsock2.h>
#include <ws2tcpip.h>

// CMake 会通过 target_link_libraries 链接 ws2_32.lib

/**
 * 对指定 IP 和端口执行一次 TCP Connect 扫描。
 *
 * @param ip   目标 IP 地址（如 "127.0.0.1"）
 * @param port 目标端口（1-65535）
 * @return     connect 成功返回 true（端口开放），失败返回 false
 *
 * 注意：调用前需已在 main 中完成 WSAStartup()。
 */
bool scanPort(const std::string& ip, int port) {
    // ----------------------------------------------------------------
    // socket()：创建 TCP 套接字
    // ----------------------------------------------------------------
    // 参数说明：
    //   AF_INET      - 使用 IPv4 地址族
    //   SOCK_STREAM  - 面向流的套接字（TCP）
    //   IPPROTO_TCP  - 明确指定 TCP 协议（也可填 0，由系统根据 SOCK_STREAM 选择）
    //
    // 返回值是一个 SOCKET 句柄，相当于后续网络操作的"端点"。
    // INVALID_SOCKET 表示创建失败。
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "socket() 失败，错误码: " << WSAGetLastError() << std::endl;
        return false;
    }

    // ----------------------------------------------------------------
    // 填充目标地址结构 sockaddr_in
    // ----------------------------------------------------------------
    sockaddr_in targetAddr{};
    targetAddr.sin_family = AF_INET;                          // IPv4
    targetAddr.sin_port = htons(static_cast<u_short>(port));   // 端口转网络字节序

    // inet_pton：将字符串 IP（如 "127.0.0.1"）转为二进制地址存入 sin_addr
    if (inet_pton(AF_INET, ip.c_str(), &targetAddr.sin_addr) != 1) {
        std::cerr << "IP 地址格式无效: " << ip << std::endl;
        closesocket(sock);
        return false;
    }

    // ----------------------------------------------------------------
    // connect()：向目标发起 TCP 连接（Connect 扫描的核心）
    // ----------------------------------------------------------------
    // 底层会发送 SYN 包，完成三次握手：
    //   客户端 SYN → 服务端 SYN-ACK → 客户端 ACK
    //
    // 返回值：
    //   0  - 连接建立成功，端口很可能开放
    //   非0 - 连接失败（端口关闭、无监听、或被防火墙拒绝等）
    int result = connect(sock,
                         reinterpret_cast<sockaddr*>(&targetAddr),
                         sizeof(targetAddr));

    // ----------------------------------------------------------------
    // closesocket()：关闭套接字，释放系统资源
    // ----------------------------------------------------------------
    // 扫描只需判断能否连上，不需要保持连接。
    // 每次扫描后必须关闭，避免句柄泄漏。
    closesocket(sock);

    return result == 0;
}

int main() {
    std::cout << "SimplePortScanner - TCP Port Scanner" << std::endl;
    std::cout << "------------------------------------" << std::endl;

    // ----------------------------------------------------------------
    // WSAStartup()：初始化 Winsock 库
    // ----------------------------------------------------------------
    // Windows 上使用 Socket 前必须先调用此函数，加载 ws2_32.dll 等依赖。
    //
    // MAKEWORD(2, 2) 表示请求 Winsock 2.2 版本。
    // wsaData 会回填实际加载的版本信息。
    //
    // 整个程序通常只需调用一次 WSAStartup，在退出前配对调用 WSACleanup。
    WSADATA wsaData;
    int wsaResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaResult != 0) {
        std::cerr << "WSAStartup 失败，错误码: " << wsaResult << std::endl;
        return 1;
    }

    // 读取用户输入
    std::string targetIp;
    int targetPort;

    std::cout << "请输入目标 IP: ";
    std::cin >> targetIp;

    std::cout << "请输入目标端口: ";
    std::cin >> targetPort;

    if (targetPort < 1 || targetPort > 65535) {
        std::cerr << "端口范围无效，应为 1-65535" << std::endl;
        WSACleanup();
        return 1;
    }

    // 执行扫描
    bool isOpen = scanPort(targetIp, targetPort);

    // 按约定格式输出结果
    if (isOpen) {
        std::cout << "[OPEN] " << targetIp << ":" << targetPort << std::endl;
    } else {
        std::cout << "[CLOSED] " << targetIp << ":" << targetPort << std::endl;
    }

    // ----------------------------------------------------------------
    // WSACleanup()：释放 Winsock 库资源
    // ----------------------------------------------------------------
    // 与 WSAStartup 配对使用，程序结束前调用。
    // 释放 WSAStartup 分配的内部资源。
    WSACleanup();

    return 0;
}
