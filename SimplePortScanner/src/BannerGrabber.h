#pragma once

#include <string>

#include <winsock2.h>

// 对已建立 TCP 连接的开放端口尝试获取 Banner
// connectedSocket：connect 成功后的套接字（调用方负责 closesocket）
// port：目标端口，用于判断是否发送 HTTP HEAD 请求
// timeoutMs：收发超时（默认建议 1000ms）
std::string grabBanner(SOCKET connectedSocket, int port, int timeoutMs = 1000);
