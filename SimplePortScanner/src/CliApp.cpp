#include "CliApp.h"

#include "ConsoleUtil.h"
#include "HostDiscovery.h"
#include "IpParser.h"
#include "LocalNetwork.h"
#include "PortParser.h"
#include "ResultWriter.h"
#include "Scanner.h"
#include "ServiceMap.h"

#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

namespace {

struct ScanConfig {
    std::vector<std::string> ips;
    std::vector<int> ports;
    int timeoutMs = 500;
    int threadCount = 10;
    bool exportResults = false;
    std::string exportFilename = "result.csv";
};

std::string toLower(std::string text) {
    for (char& ch : text) {
        if (ch >= 'A' && ch <= 'Z') {
            ch = static_cast<char>(ch - 'A' + 'a');
        }
    }
    return text;
}

bool endsWithIgnoreCase(const std::string& text, const std::string& suffix) {
    if (text.size() < suffix.size()) {
        return false;
    }
    return toLower(text.substr(text.size() - suffix.size())) == toLower(suffix);
}

template <typename Container>
void printParsedList(const char* label, const Container& items) {
    std::cout << label;
    for (size_t i = 0; i < items.size(); ++i) {
        if (i > 0) {
            std::cout << ' ';
        }
        std::cout << items[i];
    }
    std::cout << std::endl;
}

void saveResults(const std::vector<ScanResult>& openResults, const std::string& filename) {
    if (endsWithIgnoreCase(filename, ".txt")) {
        writeTxt(openResults, filename);
        std::cout << "结果已保存到 TXT 文件: " << filename << std::endl;
    } else {
        writeCsv(openResults, filename);
        std::cout << "结果已保存到 CSV 文件: " << filename << std::endl;
    }
}

void printMenu() {
    std::cout << std::endl;
    std::cout << "SimplePortScanner" << std::endl;
    std::cout << "1. 开始扫描" << std::endl;
    std::cout << "2. 查看常见端口列表" << std::endl;
    std::cout << "3. 查看使用说明" << std::endl;
    std::cout << "4. 子网主机发现" << std::endl;
    std::cout << "0. 退出" << std::endl;
}

void showKnownPorts() {
    std::cout << std::endl;
    std::cout << "常见端口列表（默认服务名，仅供参考）" << std::endl;
    std::cout << "------------------------------------" << std::endl;
    std::cout << std::left << std::setw(8) << "端口" << "服务" << std::endl;

    for (const ServiceEntry& service : getKnownServices()) {
        std::cout << std::left << std::setw(8) << service.port << service.name << std::endl;
    }
}

void showHelp() {
    std::cout << std::endl;
    std::cout << "SimplePortScanner 使用说明" << std::endl;
    std::cout << "====================================" << std::endl;
    std::cout << "1. 扫描方式" << std::endl;
    std::cout << "   - TCP Connect 扫描：通过 connect() 完成三次握手判断端口状态" << std::endl;
    std::cout << "   - 支持连接超时、多线程并发扫描" << std::endl;
    std::cout << std::endl;
    std::cout << "2. IP 表达式示例" << std::endl;
    std::cout << "   - 单个 IP：192.168.1.10" << std::endl;
    std::cout << "   - IP 范围：192.168.1.1-192.168.1.20（同一 C 段）" << std::endl;
    std::cout << "   - 多个 IP：192.168.1.1,192.168.1.10,192.168.1.20" << std::endl;
    std::cout << std::endl;
    std::cout << "3. 端口表达式示例" << std::endl;
    std::cout << "   - 单端口：80" << std::endl;
    std::cout << "   - 范围：1-1024" << std::endl;
    std::cout << "   - 多个端口：21,22,80,443" << std::endl;
    std::cout << "   - 混合：21,22,80,1000-1010" << std::endl;
    std::cout << std::endl;
    std::cout << "4. 输出说明" << std::endl;
    std::cout << "   - [OPEN]  端口开放" << std::endl;
    std::cout << "   - closed / timeout 仅统计，不逐条打印" << std::endl;
    std::cout << "   - 服务名来自默认端口映射，不代表真实协议" << std::endl;
    std::cout << std::endl;
    std::cout << "5. 结果导出" << std::endl;
    std::cout << "   - 支持 CSV / TXT" << std::endl;
    std::cout << "   - 默认文件名 result.csv" << std::endl;
    std::cout << std::endl;
    std::cout << "6. 安全提示" << std::endl;
    std::cout << "   - 仅扫描本机、虚拟机或已授权的主机" << std::endl;
    std::cout << "   - 请勿对未授权目标进行扫描" << std::endl;
    std::cout << std::endl;
    std::cout << "7. 子网主机发现" << std::endl;
    std::cout << "   - 自动识别本机 /24 子网" << std::endl;
    std::cout << "   - 用 TCP Connect 探测存活主机（80/443/135/445/22）" << std::endl;
    std::cout << "   - 可将存活 IP 带入端口扫描" << std::endl;
}

std::vector<std::string> readIpExpression() {
    while (true) {
        const std::string expression = readNonEmptyLine(
            "请输入目标 IP 或 IP 范围（如 192.168.1.10 或 192.168.1.1-192.168.1.20）: ");

        std::string errorMessage;
        const std::vector<std::string> ips = parseIPs(expression, errorMessage);
        if (!ips.empty()) {
            printParsedList("IP 解析结果：", ips);
            return ips;
        }

        std::cout << "IP 表达式无效: " << errorMessage << std::endl;
    }
}

std::vector<int> readPortExpression() {
    while (true) {
        const std::string expression = readNonEmptyLine(
            "请输入端口表达式（如 80 / 1-1024 / 21,22,80,443）: ");

        std::string errorMessage;
        const std::vector<int> ports = parsePorts(expression, errorMessage);
        if (!ports.empty()) {
            printParsedList("端口解析结果：", ports);
            return ports;
        }

        std::cout << "端口表达式无效: " << errorMessage << std::endl;
    }
}

ScanConfig collectScanConfig(const std::vector<std::string>* presetIps) {
    ScanConfig config{};

    if (presetIps != nullptr && !presetIps->empty()) {
        config.ips = *presetIps;
        printParsedList("使用存活 IP 列表：", config.ips);
    } else {
        config.ips = readIpExpression();
    }
    config.ports = readPortExpression();

    config.timeoutMs = readIntInRange(
        "请输入超时时间（毫秒，如 500 或 1000）: ", 1, 600000);

    config.threadCount = readIntInRange(
        "请输入线程数（如 10 / 50 / 100）: ", 1, 1000);

    config.exportResults = readYesNo("是否导出扫描结果？(y/n): ");
    if (config.exportResults) {
        std::string filename = readLine("请输入文件名（直接回车默认 result.csv）: ");
        if (filename.empty()) {
            filename = "result.csv";
        }
        config.exportFilename = filename;
    }

    return config;
}

void printScanSummary(const RangeScanSummary& summary,
                      const std::string& startTime,
                      const std::string& endTime) {
    std::cout << std::endl;
    std::cout << "扫描摘要" << std::endl;
    std::cout << "------------------------------------" << std::endl;
    std::cout << "开始时间：" << startTime << std::endl;
    std::cout << "结束时间：" << endTime << std::endl;
    std::cout << "扫描主机数：" << summary.hostCount << std::endl;
    std::cout << "扫描端口数：" << summary.portCount << std::endl;
    std::cout << "总任务数：" << summary.totalTasks << std::endl;
    std::cout << "开放端口数：" << summary.openPorts << std::endl;
    std::cout << "关闭端口数：" << summary.closedPorts << std::endl;
    std::cout << "超时端口数：" << summary.timeoutPorts << std::endl;
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "总耗时：" << summary.elapsedSeconds << " 秒" << std::endl;
}

void runScan(const std::vector<std::string>* presetIps) {
    const ScanConfig config = collectScanConfig(presetIps);
    const int totalTasks = static_cast<int>(config.ips.size() * config.ports.size());

    std::cout << std::endl;
    std::cout << "即将扫描 " << config.ips.size() << " 个 IP × "
              << config.ports.size() << " 个端口 = "
              << totalTasks << " 个任务" << std::endl;
    std::cout << "超时 " << config.timeoutMs << " ms，线程数 "
              << config.threadCount << std::endl;

    const std::string startTime = currentDateTimeString();
    std::cout << "开始时间：" << startTime << std::endl;
    std::cout << "扫描进行中，请稍候..." << std::endl << std::endl;

    std::vector<ScanResult> openResults;
    const RangeScanSummary summary = scanTargetsConcurrent(
        config.ips,
        config.ports,
        config.timeoutMs,
        config.threadCount,
        &openResults);

    const std::string endTime = currentDateTimeString();
    printScanSummary(summary, startTime, endTime);

    if (config.exportResults) {
        try {
            saveResults(openResults, config.exportFilename);
        } catch (const std::exception& ex) {
            std::cout << "导出失败: " << ex.what() << std::endl;
        }
    }
}

LocalSubnet chooseLocalSubnet() {
    const std::vector<LocalSubnet> subnets = getLocalSubnets();
    if (subnets.empty()) {
        std::cout << "未找到可用的 /24 子网网卡。请确认网卡已连接且掩码为 255.255.255.0。" << std::endl;
        return {};
    }

    std::cout << std::endl;
    std::cout << "检测到以下本机子网：" << std::endl;
    std::cout << "------------------------------------" << std::endl;
    for (size_t i = 0; i < subnets.size(); ++i) {
        const LocalSubnet& subnet = subnets[i];
        std::cout << (i + 1) << ". " << subnet.adapterName
                  << " | 本机 IP: " << subnet.localIp
                  << " | 子网: " << subnet.cidr
                  << " | 扫描范围: " << subnet.scanRange << std::endl;
    }

    if (subnets.size() == 1) {
        std::cout << std::endl << "自动选择唯一可用子网。" << std::endl;
        return subnets.front();
    }

    const int choice = readIntInRange("请选择要探测的子网编号: ", 1, static_cast<int>(subnets.size()));
    return subnets[static_cast<size_t>(choice - 1)];
}

void printDiscoverySummary(const HostDiscoverySummary& summary) {
    std::cout << std::endl;
    std::cout << "探测完成：" << std::endl;
    std::cout << "存活主机：" << summary.aliveHosts << " / " << summary.totalHosts << std::endl;
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "总耗时：" << summary.elapsedSeconds << " 秒" << std::endl;
}

void runSubnetDiscovery() {
    const LocalSubnet subnet = chooseLocalSubnet();
    if (subnet.scanRange.empty()) {
        return;
    }

    std::string parseError;
    const std::vector<std::string> ips = parseIPs(subnet.scanRange, parseError);
    if (ips.empty()) {
        std::cout << "IP 范围解析失败: " << parseError << std::endl;
        return;
    }

    std::cout << std::endl;
    std::cout << "即将探测子网 " << subnet.cidr
              << "，共 " << ips.size() << " 个 IP" << std::endl;
    std::cout << "探测端口：80, 443, 135, 445, 22（任一响应即判定存活）" << std::endl;

    const int timeoutMs = readIntInRange(
        "请输入超时时间（毫秒，如 300 或 500）: ", 1, 600000);
    const int threadCount = readIntInRange(
        "请输入线程数（如 20 / 50 / 100）: ", 1, 1000);

    std::cout << std::endl;
    std::cout << "子网探测进行中，请稍候..." << std::endl;

    const HostDiscoverySummary summary = discoverHosts(ips, timeoutMs, threadCount);

    if (summary.results.empty()) {
        std::cout << std::endl << "未发现存活主机。" << std::endl;
    } else {
        std::cout << std::endl;
        for (const HostProbeResult& result : summary.results) {
            std::cout << "[ALIVE] " << result.ip
                      << " (响应端口 " << result.respondedPort << ") "
                      << result.timeMs << " ms" << std::endl;
        }
    }

    printDiscoverySummary(summary);

    if (summary.aliveHosts == 0) {
        return;
    }

    if (!readYesNo("是否使用存活 IP 继续端口扫描？(y/n): ")) {
        return;
    }

    std::vector<std::string> aliveIps;
    aliveIps.reserve(summary.results.size());
    for (const HostProbeResult& result : summary.results) {
        aliveIps.push_back(result.ip);
    }

    runScan(&aliveIps);
}

}  // namespace

void CliApp::run() {
    while (true) {
        printMenu();

        const int choice = readIntInRange("请选择: ", 0, 4);

        switch (choice) {
            case 1:
                runScan(nullptr);
                pauseForEnter();
                break;
            case 2:
                showKnownPorts();
                pauseForEnter();
                break;
            case 3:
                showHelp();
                pauseForEnter();
                break;
            case 4:
                runSubnetDiscovery();
                pauseForEnter();
                break;
            case 0:
                std::cout << "感谢使用 SimplePortScanner，再见！" << std::endl;
                return;
            default:
                break;
        }
    }
}
