#include "HostDiscovery.h"

#include <chrono>
#include <mutex>
#include <queue>
#include <thread>

namespace {

// ----------------------------------------------------------------
// probeHostAlive：对单个 IP 用多个端口做 TCP Connect 探测
// ----------------------------------------------------------------
// Open 或 Closed（RST）均表示主机在线；全部 Timeout 视为无响应。
HostProbeResult probeHostAlive(const std::string& ip,
                               int timeoutMs,
                               const std::vector<int>& probePorts) {
    HostProbeResult result{};
    result.ip = ip;

    for (int port : probePorts) {
        const ScanResult scanResult = scanPortWithTimeout(ip, port, timeoutMs);
        if (scanResult.status != PortStatus::Timeout) {
            result.alive = true;
            result.respondedPort = port;
            result.status = scanResult.status;
            result.timeMs = scanResult.timeMs;
            return result;
        }
    }

    return result;
}

}  // namespace

std::vector<int> defaultProbePorts() {
    return {80, 443, 135, 445, 22};
}

HostDiscoverySummary discoverHosts(const std::vector<std::string>& ips,
                                   int timeoutMs,
                                   int threadCount,
                                   const std::vector<int>& probePorts) {
    HostDiscoverySummary summary{};
    summary.totalHosts = static_cast<int>(ips.size());

    if (ips.empty() || probePorts.empty()) {
        return summary;
    }

    if (threadCount < 1) {
        threadCount = 1;
    }
    if (threadCount > summary.totalHosts) {
        threadCount = summary.totalHosts;
    }

    std::queue<std::string> taskQueue;
    for (const std::string& ip : ips) {
        taskQueue.push(ip);
    }

    std::vector<HostProbeResult> aliveResults;
    aliveResults.reserve(static_cast<size_t>(summary.totalHosts / 4 + 1));

    std::mutex queueMutex;
    std::mutex resultMutex;

    auto worker = [&]() {
        while (true) {
            std::string ip;

            {
                std::lock_guard<std::mutex> lock(queueMutex);
                if (taskQueue.empty()) {
                    break;
                }
                ip = taskQueue.front();
                taskQueue.pop();
            }

            const HostProbeResult probeResult = probeHostAlive(ip, timeoutMs, probePorts);
            if (probeResult.alive) {
                std::lock_guard<std::mutex> lock(resultMutex);
                aliveResults.push_back(probeResult);
            }
        }
    };

    const auto startTime = std::chrono::steady_clock::now();

    std::vector<std::thread> workers;
    workers.reserve(static_cast<size_t>(threadCount));
    for (int i = 0; i < threadCount; ++i) {
        workers.emplace_back(worker);
    }

    for (std::thread& workerThread : workers) {
        workerThread.join();
    }

    const auto endTime = std::chrono::steady_clock::now();
    summary.elapsedSeconds = std::chrono::duration<double>(endTime - startTime).count();
    summary.aliveHosts = static_cast<int>(aliveResults.size());
    summary.results = std::move(aliveResults);

    return summary;
}
