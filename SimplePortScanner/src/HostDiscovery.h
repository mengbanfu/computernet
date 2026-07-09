#pragma once

#include "Scanner.h"

#include <string>
#include <vector>

// 单台主机的存活探测结果
struct HostProbeResult {
    std::string ip;
    bool alive = false;
    int respondedPort = 0;   // 首个有 TCP 响应的探测端口，0 表示无
    PortStatus status = PortStatus::Timeout;
    long long timeMs = 0;
};

// 子网主机发现汇总
struct HostDiscoverySummary {
    int totalHosts = 0;
    int aliveHosts = 0;
    double elapsedSeconds = 0.0;
    std::vector<HostProbeResult> results;  // 仅包含存活主机
};

// 默认探测端口：80, 443, 135, 445, 22
std::vector<int> defaultProbePorts();

// 对 IP 列表执行 TCP Connect 存活探测（多线程）
HostDiscoverySummary discoverHosts(const std::vector<std::string>& ips,
                                   int timeoutMs,
                                   int threadCount,
                                   const std::vector<int>& probePorts = defaultProbePorts());
