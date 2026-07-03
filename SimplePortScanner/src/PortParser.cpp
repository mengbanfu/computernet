#include "PortParser.h"

#include <algorithm>
#include <sstream>
#include <unordered_set>

namespace {

constexpr int kMinPort = 1;
constexpr int kMaxPort = 65535;

std::string trim(const std::string& text) {
    const auto start = text.find_first_not_of(" \t");
    if (start == std::string::npos) {
        return "";
    }
    const auto end = text.find_last_not_of(" \t");
    return text.substr(start, end - start + 1);
}

bool isValidPort(int port) {
    return port >= kMinPort && port <= kMaxPort;
}

// 严格解析整数：整段字符串必须全部是数字，不允许 "80abc"
bool parseInteger(const std::string& text, int& value) {
    if (text.empty()) {
        return false;
    }

    try {
        size_t consumed = 0;
        const long long parsed = std::stoll(text, &consumed);
        if (consumed != text.size()) {
            return false;
        }
        if (parsed < kMinPort || parsed > kMaxPort) {
            value = static_cast<int>(parsed);
            return true;  // 数值可解析，但可能超出合法端口范围，由调用方过滤
        }
        value = static_cast<int>(parsed);
        return true;
    } catch (...) {
        return false;
    }
}

void addPort(int port, std::vector<int>& ports, std::unordered_set<int>& seen) {
    if (!isValidPort(port) || seen.count(port) > 0) {
        return;
    }
    seen.insert(port);
    ports.push_back(port);
}

bool parseSinglePortToken(const std::string& token, std::vector<int>& ports,
                          std::unordered_set<int>& seen, std::string& errorMessage) {
    int port = 0;
    if (!parseInteger(token, port)) {
        errorMessage = "非法端口: " + token;
        return false;
    }
    addPort(port, ports, seen);
    return true;
}

bool parseRangeToken(const std::string& token, std::vector<int>& ports,
                     std::unordered_set<int>& seen, std::string& errorMessage) {
    const size_t dashPos = token.find('-');
    if (dashPos == std::string::npos || dashPos == 0 || dashPos == token.size() - 1) {
        errorMessage = "非法端口范围: " + token;
        return false;
    }

    // 只允许一个 '-'，避免 "1-2-3" 这类歧义输入
    if (token.find('-', dashPos + 1) != std::string::npos) {
        errorMessage = "非法端口范围: " + token;
        return false;
    }

    const std::string startText = token.substr(0, dashPos);
    const std::string endText = token.substr(dashPos + 1);

    int startPort = 0;
    int endPort = 0;
    if (!parseInteger(startText, startPort) || !parseInteger(endText, endPort)) {
        errorMessage = "非法端口范围: " + token;
        return false;
    }

    if (startPort > endPort) {
        errorMessage = "端口范围起始值不能大于结束值: " + token;
        return false;
    }

    // 自动过滤：只展开 1-65535 内的部分
    const int rangeStart = std::max(startPort, kMinPort);
    const int rangeEnd = std::min(endPort, kMaxPort);
    for (int port = rangeStart; port <= rangeEnd; ++port) {
        addPort(port, ports, seen);
    }

    return true;
}

std::vector<std::string> splitByComma(const std::string& input) {
    std::vector<std::string> tokens;
    std::stringstream stream(input);
    std::string item;

    while (std::getline(stream, item, ',')) {
        tokens.push_back(trim(item));
    }

    return tokens;
}

}  // namespace

std::vector<int> parsePorts(const std::string& input, std::string& errorMessage) {
    errorMessage.clear();

    const std::string normalizedInput = trim(input);
    if (normalizedInput.empty()) {
        errorMessage = "端口表达式不能为空";
        return {};
    }

    const std::vector<std::string> tokens = splitByComma(normalizedInput);
    if (tokens.empty()) {
        errorMessage = "端口表达式不能为空";
        return {};
    }

    std::vector<int> ports;
    std::unordered_set<int> seen;
    ports.reserve(tokens.size());

    for (const std::string& token : tokens) {
        if (token.empty()) {
            errorMessage = "端口表达式中存在空项，请检查逗号分隔格式";
            return {};
        }

        const bool isRange = token.find('-') != std::string::npos;
        const bool ok = isRange ? parseRangeToken(token, ports, seen, errorMessage)
                                : parseSinglePortToken(token, ports, seen, errorMessage);
        if (!ok) {
            return {};
        }
    }

    if (ports.empty()) {
        errorMessage = "没有有效的端口（合法范围为 1-65535）";
        return {};
    }

    return ports;
}

std::vector<int> parsePorts(const std::string& input) {
    std::string errorMessage;
    return parsePorts(input, errorMessage);
}
