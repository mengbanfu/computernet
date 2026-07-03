#pragma once

#include <string>
#include <vector>

// 解析端口表达式，支持：80 / 1-1024 / 21,22,80 / 21,22,80,1000-1010
// 自动去重；仅保留 1-65535 范围内的合法端口
std::vector<int> parsePorts(const std::string& input);

// 解析失败时返回空 vector，并通过 errorMessage 给出原因
std::vector<int> parsePorts(const std::string& input, std::string& errorMessage);
