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
    long long timeMs = 0;       // 本次扫描耗时（毫秒）
    std::string banner;         // 开放端口尝试获取的 Banner（可能为空）
};

// 扫描任务：一个 IP + 一个端口
struct ScanTask {
    std::string ip;
    int port = 0;
};

// 扫描汇总统计
struct RangeScanSummary {
    int hostCount = 0;        // 扫描主机数
    int portCount = 0;        // 扫描端口数（表达式解析后的端口种类数）
    int totalTasks = 0;       // 总任务数 = 主机数 × 端口数
    int openPorts = 0;
    int closedPorts = 0;      // 内部统计，不逐条打印
    int timeoutPorts = 0;       // 内部统计，不逐条打印
    double elapsedSeconds = 0.0;
};

// 对单个端口执行 TCP Connect 扫描（无超时，阻塞式）
bool scanPort(const std::string& ip, int port);

// 对单个端口执行带超时的 TCP Connect 扫描（非阻塞 + select）
ScanResult scanPortWithTimeout(const std::string& ip, int port, int timeoutMs);

// 单线程扫描（保留，内部转发到 1 线程并发版本）
RangeScanSummary scanPortRange(const std::string& ip, int startPort, int endPort, int timeoutMs);
RangeScanSummary scanPorts(const std::string& ip, const std::vector<int>& ports, int timeoutMs);
RangeScanSummary scanTargets(const std::vector<std::string>& ips,
                             const std::vector<int>& ports,
                             int timeoutMs);

// 多线程扫描：任务队列 + 工作线程并发执行
// openResultsOut 若非空，扫描结束后回填开放端口列表（供导出使用）
RangeScanSummary scanTargetsConcurrent(const std::vector<std::string>& ips,
                                       const std::vector<int>& ports,
                                       int timeoutMs,
                                       int threadCount,
                                       std::vector<ScanResult>* openResultsOut = nullptr,
                                       bool printOpenResults = true);

// 将单端口扫描结果按约定格式输出
void printPortScanResult(const ScanResult& result);
