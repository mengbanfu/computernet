#include "ResultWriter.h"

#include "ServiceMap.h"

#include <fstream>
#include <iomanip>
#include <stdexcept>

namespace {

std::string statusToString(PortStatus status) {
    switch (status) {
        case PortStatus::Open:
            return "Open";
        case PortStatus::Closed:
            return "Closed";
        case PortStatus::Timeout:
            return "Timeout";
    }
    return "Unknown";
}

// 默认只导出开放端口
std::vector<ScanResult> filterOpenResults(const std::vector<ScanResult>& results) {
    std::vector<ScanResult> openResults;
    openResults.reserve(results.size());
    for (const ScanResult& result : results) {
        if (result.status == PortStatus::Open) {
            openResults.push_back(result);
        }
    }
    return openResults;
}

}  // namespace

void writeTxt(const std::vector<ScanResult>& results, const std::string& filename) {
    const std::vector<ScanResult> openResults = filterOpenResults(results);

    std::ofstream out(filename, std::ios::out | std::ios::trunc);
    if (!out) {
        throw std::runtime_error("无法写入 TXT 文件: " + filename);
    }

    out << "SimplePortScanner 扫描结果\n";
    out << "================================\n";
    out << "说明：以下仅列出开放端口（Open）\n";
    out << "================================\n\n";

    if (openResults.empty()) {
        out << "未发现开放端口。\n";
        return;
    }

    for (const ScanResult& result : openResults) {
        out << "[OPEN] " << result.ip << ':' << result.port << ' '
            << getServiceName(result.port);
        if (!result.banner.empty()) {
            out << ' ' << result.banner;
        }
        out << " (耗时 " << result.timeMs << " ms)\n";
    }

    out << "\n--------------------------------\n";
    out << "开放端口总数：" << openResults.size() << '\n';
}

void writeCsv(const std::vector<ScanResult>& results, const std::string& filename) {
    const std::vector<ScanResult> openResults = filterOpenResults(results);

    std::ofstream out(filename, std::ios::out | std::ios::trunc);
    if (!out) {
        throw std::runtime_error("无法写入 CSV 文件: " + filename);
    }

    out << "IP,Port,Status,Service,Banner,TimeMs\n";

    for (const ScanResult& result : openResults) {
        out << result.ip << ','
            << result.port << ','
            << statusToString(result.status) << ','
            << getServiceName(result.port) << ','
            << result.banner << ','
            << result.timeMs << '\n';
    }
}
