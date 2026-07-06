#pragma once

#include <string>
#include <utility>
#include <vector>

struct ServiceEntry {
    int port = 0;
    std::string name;
};

// 根据端口号返回常见服务名称（基于 IANA 默认端口映射）
// 未知端口返回 "Unknown"
std::string getServiceName(int port);

// 返回内置常见端口列表（按端口号升序）
std::vector<ServiceEntry> getKnownServices();