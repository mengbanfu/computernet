#pragma once

#include <string>
#include <vector>

// 单个端口的扫描状态
enum class PortStatus {
    Open,     // connect 在超时内成功：端口开放，有进程在监听
    Closed,   // connect 立即失败或被拒绝：端口关闭
    Timeout   // 超时内无明确响应：可能被过滤或网络丢弃（filtered）
};

// 单个端口的扫描结果
struct ScanResult {
    std::string ip;
    int port = 0;
    PortStatus status = PortStatus::Closed;
    long long timeMs = 0;  // 本次扫描耗时（毫秒）
};

// 端口范围扫描的汇总统计
struct RangeScanSummary {
    int totalPorts = 0;
    int openPorts = 0;
    int closedPorts = 0;
    int timeoutPorts = 0;
    double elapsedSeconds = 0.0;
};

// 对单个端口执行 TCP Connect 扫描（无超时，阻塞式）
bool scanPort(const std::string& ip, int port);

// 对单个端口执行带超时的 TCP Connect 扫描（非阻塞 + select）
// 返回 ScanResult 而非 bool，因为 Open / Closed / Timeout 三种状态无法用 bool 区分
ScanResult scanPortWithTimeout(const std::string& ip, int port, int timeoutMs);

// 依次扫描端口范围，使用超时控制；关闭端口不打印，避免刷屏
RangeScanSummary scanPortRange(const std::string& ip, int startPort, int endPort, int timeoutMs);

// 扫描指定端口列表（通常由 parsePorts 解析得到）
RangeScanSummary scanPorts(const std::string& ip, const std::vector<int>& ports, int timeoutMs);

// 将单端口扫描结果按约定格式输出
void printPortScanResult(const ScanResult& result);
