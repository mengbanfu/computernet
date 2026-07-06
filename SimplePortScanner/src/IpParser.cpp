#include "IpParser.h"

#include <array>
#include <sstream>
#include <string>
#include <vector>

namespace {

std::string trim(const std::string& text) {
    const auto start = text.find_first_not_of(" \t");
    if (start == std::string::npos) {
        return "";
    }
    const auto end = text.find_last_not_of(" \t");
    return text.substr(start, end - start + 1);
}

bool parseIntegerStrict(const std::string& text, int& value) {
    if (text.empty()) {
        return false;
    }

    try {
        size_t consumed = 0;
        const long long parsed = std::stoll(text, &consumed);
        if (consumed != text.size()) {
            return false;
        }
        if (parsed < 0 || parsed > 255) {
            return false;
        }
        value = static_cast<int>(parsed);
        return true;
    } catch (...) {
        return false;
    }
}

// 校验 IPv4 格式：必须是 a.b.c.d，每段 0-255，且恰好 4 段
bool parseIPv4(const std::string& ipText, std::array<int, 4>& octets) {
    std::vector<std::string> parts;
    std::stringstream stream(ipText);
    std::string part;

    while (std::getline(stream, part, '.')) {
        if (part.empty()) {
            return false;
        }
        parts.push_back(part);
    }

    if (parts.size() != 4) {
        return false;
    }

    for (size_t i = 0; i < parts.size(); ++i) {
        if (!parseIntegerStrict(parts[i], octets[i])) {
            return false;
        }
    }

    return true;
}

std::string formatIPv4(const std::array<int, 4>& octets) {
    std::ostringstream output;
    output << octets[0] << '.'
           << octets[1] << '.'
           << octets[2] << '.'
           << octets[3];
    return output.str();
}

bool isSameCClassSubnet(const std::array<int, 4>& startIp, const std::array<int, 4>& endIp) {
    return startIp[0] == endIp[0]
        && startIp[1] == endIp[1]
        && startIp[2] == endIp[2];
}

bool parseSingleIp(const std::string& token, std::vector<std::string>& ips, std::string& errorMessage) {
    std::array<int, 4> octets{};
    if (!parseIPv4(token, octets)) {
        errorMessage = "非法 IP 地址: " + token;
        return false;
    }

    ips.push_back(formatIPv4(octets));
    return true;
}

bool parseIpRange(const std::string& input, std::vector<std::string>& ips, std::string& errorMessage) {
    const size_t dashPos = input.find('-');
    if (dashPos == std::string::npos || dashPos == 0 || dashPos == input.size() - 1) {
        errorMessage = "非法 IP 范围: " + input;
        return false;
    }

    const std::string startText = trim(input.substr(0, dashPos));
    const std::string endText = trim(input.substr(dashPos + 1));

    std::array<int, 4> startIp{};
    std::array<int, 4> endIp{};
    if (!parseIPv4(startText, startIp)) {
        errorMessage = "非法起始 IP: " + startText;
        return false;
    }
    if (!parseIPv4(endText, endIp)) {
        errorMessage = "非法结束 IP: " + endText;
        return false;
    }

    if (!isSameCClassSubnet(startIp, endIp)) {
        errorMessage = "IP 范围必须在同一 C 段内，例如 192.168.1.1-192.168.1.20";
        return false;
    }

    if (startIp[3] > endIp[3]) {
        errorMessage = "IP 范围起始地址不能大于结束地址: " + input;
        return false;
    }

    for (int host = startIp[3]; host <= endIp[3]; ++host) {
        std::array<int, 4> currentIp = startIp;
        currentIp[3] = host;
        ips.push_back(formatIPv4(currentIp));
    }

    return true;
}

}  // namespace

std::vector<std::string> parseIPs(const std::string& input, std::string& errorMessage) {
    errorMessage.clear();

    const std::string normalizedInput = trim(input);
    if (normalizedInput.empty()) {
        errorMessage = "IP 表达式不能为空";
        return {};
    }

    std::vector<std::string> ips;

    const bool isRange = normalizedInput.find('-') != std::string::npos;
    const bool ok = isRange ? parseIpRange(normalizedInput, ips, errorMessage)
                            : parseSingleIp(normalizedInput, ips, errorMessage);
    if (!ok) {
        return {};
    }

    if (ips.empty()) {
        errorMessage = "没有有效的 IP 地址";
        return {};
    }

    return ips;
}

std::vector<std::string> parseIPs(const std::string& input) {
    std::string errorMessage;
    return parseIPs(input, errorMessage);
}
