#include "ServiceMap.h"

#include <algorithm>
#include <unordered_map>
#include <vector>
namespace {

// 常见 TCP 端口与默认服务名对照表
// 注意：这只是“默认端口 → 服务名”的静态映射，并非实际探测协议
const std::unordered_map<int, std::string> kServiceMap = {
    {20,   "FTP-DATA"},
    {21,   "FTP"},
    {22,   "SSH"},
    {23,   "Telnet"},
    {25,   "SMTP"},
    {53,   "DNS"},
    {67,   "DHCP"},
    {68,   "DHCP"},
    {80,   "HTTP"},
    {110,  "POP3"},
    {123,  "NTP"},
    {143,  "IMAP"},
    {161,  "SNMP"},
    {443,  "HTTPS"},
    {445,  "SMB"},
    {3306, "MySQL"},
    {3389, "RDP"},
    {6379, "Redis"},
    {8080, "HTTP-Proxy"},
};

}  // namespace

std::string getServiceName(int port) {
    const auto it = kServiceMap.find(port);
    if (it != kServiceMap.end()) {
        return it->second;
    }
    return "Unknown";
}

std::vector<ServiceEntry> getKnownServices() {
    std::vector<ServiceEntry> services;
    services.reserve(kServiceMap.size());

    for (const auto& item : kServiceMap) {
        services.push_back(ServiceEntry{item.first, item.second});
    }

    std::sort(services.begin(), services.end(),
              [](const ServiceEntry& a, const ServiceEntry& b) {
                  return a.port < b.port;
              });

    return services;
}