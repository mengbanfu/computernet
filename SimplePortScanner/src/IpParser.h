#pragma once

#include <string>
#include <vector>

// 解析 IP 表达式，支持：
//   - 单个 IP：192.168.1.10
//   - 同 C 段范围：192.168.1.1-192.168.1.20
//   - 多个 IP：192.168.1.1,192.168.1.10,192.168.1.20
std::vector<std::string> parseIPs(const std::string& input);

// 解析失败时返回空 vector，并通过 errorMessage 给出原因
std::vector<std::string> parseIPs(const std::string& input, std::string& errorMessage);
