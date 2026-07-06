#include "CliApp.h"

#include "ConsoleUtil.h"
#include "IpParser.h"
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

ScanConfig collectScanConfig() {
    ScanConfig config{};

    config.ips = readIpExpression();
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

void runScan() {
    const ScanConfig config = collectScanConfig();
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

}  // namespace

void CliApp::run() {
    while (true) {
        printMenu();

        const int choice = readIntInRange("请选择: ", 0, 3);

        switch (choice) {
            case 1:
                runScan();
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
            case 0:
                std::cout << "感谢使用 SimplePortScanner，再见！" << std::endl;
                return;
            default:
                break;
        }
    }
}
