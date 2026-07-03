/**
 * SimplePortScanner - TCP Connect 端口扫描
 *
 * 支持：
 *   - 端口表达式解析（单端口 / 范围 / 逗号分隔 / 混合格式）
 *   - 非阻塞 connect + select() 超时控制
 */

#include "PortParser.h"
#include "Scanner.h"

#include <iostream>
#include <iomanip>
#include <string>

#include <winsock2.h>
#include <windows.h>

namespace {

void printParsedPorts(const std::vector<int>& ports) {
    std::cout << "解析结果：";
    for (size_t i = 0; i < ports.size(); ++i) {
        if (i > 0) {
            std::cout << ' ';
        }
        std::cout << ports[i];
    }
    std::cout << std::endl;
}

}  // namespace

int main() {
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);

    std::cout << "SimplePortScanner - TCP Port Scanner" << std::endl;
    std::cout << "------------------------------------" << std::endl;

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup 失败" << std::endl;
        return 1;
    }

    std::string targetIp;
    std::string portExpression;
    int timeoutMs;

    std::cout << "请输入目标 IP: ";
    std::cin >> targetIp;

    std::cout << "请输入端口表达式（如 80 / 1-1024 / 21,22,80,443 / 21,22,80,1000-1010）: ";
    std::cin >> portExpression;

    std::cout << "请输入超时时间（毫秒，如 500 或 1000）: ";
    std::cin >> timeoutMs;

    std::string parseError;
    const std::vector<int> ports = parsePorts(portExpression, parseError);
    if (ports.empty()) {
        std::cerr << "端口表达式解析失败: " << parseError << std::endl;
        WSACleanup();
        return 1;
    }

    if (timeoutMs <= 0) {
        std::cerr << "超时时间必须大于 0 毫秒" << std::endl;
        WSACleanup();
        return 1;
    }

    std::cout << std::endl;
    printParsedPorts(ports);
    std::cout << std::endl;
    std::cout << "开始扫描 " << targetIp << " 的 "
              << ports.size() << " 个端口"
              << "（超时 " << timeoutMs << " ms）..." << std::endl;
    std::cout << std::endl;

    RangeScanSummary summary = scanPorts(targetIp, ports, timeoutMs);

    std::cout << std::endl;
    std::cout << "扫描完成：" << std::endl;
    std::cout << "扫描端口数：" << summary.totalPorts << std::endl;
    std::cout << "开放端口数：" << summary.openPorts << std::endl;
    std::cout << "关闭端口数：" << summary.closedPorts << std::endl;
    std::cout << "超时端口数：" << summary.timeoutPorts << std::endl;
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "耗时：" << summary.elapsedSeconds << " 秒" << std::endl;

    WSACleanup();
    return 0;
}
