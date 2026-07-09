#pragma once

#include <string>
#include <vector>

// 本机网卡对应的 /24 子网信息
struct LocalSubnet {
    std::string adapterName;   // 网卡友好名称，如 "WLAN"
    std::string localIp;       // 本机 IPv4 地址
    std::string subnetMask;    // 子网掩码，如 "255.255.255.0"
    std::string cidr;          // 如 "192.168.1.0/24"
    std::string scanRange;     // 如 "192.168.1.1-192.168.1.254"
};

// 获取本机活跃网卡的 /24 子网列表（首版仅支持 255.255.255.0）
std::vector<LocalSubnet> getLocalSubnets();
