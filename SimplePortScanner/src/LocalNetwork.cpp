// ----------------------------------------------------------------
// LocalNetwork - 本机子网自动识别
// ----------------------------------------------------------------
// 通过 Windows GetAdaptersAddresses 读取网卡 IPv4 地址与前缀长度，
// 生成 /24 子网的扫描范围，供「子网主机发现」功能使用。
//
// 首版限制：
//   - 仅支持掩码 255.255.255.0（/24），与 IpParser 的 C 段范围能力对齐
//   - 跳过回环地址（127.x.x.x）和未连接（OperStatus != Up）的网卡
//   - 扫描范围固定为 x.y.z.1 ~ x.y.z.254（跳过网络号 .0 和广播 .255）

#include "LocalNetwork.h"

#include <array>
#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#endif

namespace {

// 将四段十进制数组格式化为 IPv4 字符串
std::string formatIPv4(const std::array<int, 4>& octets) {
    std::ostringstream output;
    output << octets[0] << '.'
           << octets[1] << '.'
           << octets[2] << '.'
           << octets[3];
    return output.str();
}

// 解析 "a.b.c.d" 为四段整数，每段须在 0-255
bool parseIPv4ToOctets(const std::string& ipText, std::array<int, 4>& octets) {
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
        try {
            const int value = std::stoi(parts[i]);
            if (value < 0 || value > 255) {
                return false;
            }
            octets[i] = value;
        } catch (...) {
            return false;
        }
    }

    return true;
}

// 判断是否为回环地址（127.0.0.0/8）
bool isLoopbackIp(const std::string& ip) {
    std::array<int, 4> octets{};
    if (!parseIPv4ToOctets(ip, octets)) {
        return false;
    }
    return octets[0] == 127;
}

#ifdef _WIN32

// 将 Windows 宽字符（网卡 FriendlyName）转为 UTF-8，便于控制台输出
std::string wideToUtf8(const wchar_t* wideText) {
    if (wideText == nullptr || wideText[0] == L'\0') {
        return "";
    }

    const int bytes = WideCharToMultiByte(CP_UTF8, 0, wideText, -1, nullptr, 0, nullptr, nullptr);
    if (bytes <= 0) {
        return "";
    }

    std::string output(static_cast<size_t>(bytes - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wideText, -1, output.data(), bytes, nullptr, nullptr);
    return output;
}

// 从 sockaddr 结构提取 IPv4 点分十进制字符串
std::string sockaddrToIpv4(const sockaddr* address) {
    if (address == nullptr) {
        return "";
    }

    char buffer[INET_ADDRSTRLEN]{};
    const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(address);
    if (inet_ntop(AF_INET, &ipv4->sin_addr, buffer, sizeof(buffer)) == nullptr) {
        return "";
    }
    return buffer;
}

// ----------------------------------------------------------------
// prefixLengthToMask：CIDR 前缀长度 → 点分十进制掩码
// ----------------------------------------------------------------
// 例如 prefixLength=24 → "255.255.255.0"
std::string prefixLengthToMask(int prefixLength) {
    if (prefixLength <= 0 || prefixLength > 32) {
        return "";
    }

    const uint32_t mask = prefixLength == 32
        ? 0xFFFFFFFFu
        : (0xFFFFFFFFu << (32 - prefixLength));

    std::array<int, 4> octets{};
    octets[0] = static_cast<int>((mask >> 24) & 0xFF);
    octets[1] = static_cast<int>((mask >> 16) & 0xFF);
    octets[2] = static_cast<int>((mask >> 8) & 0xFF);
    octets[3] = static_cast<int>(mask & 0xFF);
    return formatIPv4(octets);
}

// ----------------------------------------------------------------
// buildSlash24ScanRange：根据本机 IP 生成 /24 扫描范围
// ----------------------------------------------------------------
// 输入 192.168.1.100 → cidr=192.168.1.0/24, scanRange=192.168.1.1-192.168.1.254
bool buildSlash24ScanRange(const std::string& localIp, LocalSubnet& subnet) {
    std::array<int, 4> octets{};
    if (!parseIPv4ToOctets(localIp, octets)) {
        return false;
    }

    const std::array<int, 4> network = {
        octets[0], octets[1], octets[2], 0
    };

    subnet.cidr = formatIPv4(network) + "/24";
    subnet.scanRange = formatIPv4({octets[0], octets[1], octets[2], 1}) + '-'
                     + formatIPv4({octets[0], octets[1], octets[2], 254});
    return true;
}

#endif

}  // namespace

// ----------------------------------------------------------------
// getLocalSubnets：枚举本机所有可用的 /24 子网
// ----------------------------------------------------------------
// Windows 实现流程：
//   1. GetAdaptersAddresses 获取网卡链表
//   2. 过滤 OperStatus == Up 的网卡
//   3. 遍历每张网卡的 IPv4 单播地址
//   4. 跳过回环、非 /24 掩码的地址
//   5. 填充 LocalSubnet 并返回
std::vector<LocalSubnet> getLocalSubnets() {
    std::vector<LocalSubnet> subnets;

#ifdef _WIN32
    // GetAdaptersAddresses 采用「先试探缓冲区大小，不足则扩容」的惯用模式
    ULONG bufferSize = 15000;
    std::vector<unsigned char> buffer(bufferSize);
    PIP_ADAPTER_ADDRESSES adapters = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());

    DWORD result = GetAdaptersAddresses(
        AF_INET,
        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
        nullptr,
        adapters,
        &bufferSize);

    if (result == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(bufferSize);
        adapters = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
        result = GetAdaptersAddresses(
            AF_INET,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            nullptr,
            adapters,
            &bufferSize);
    }

    if (result != NO_ERROR) {
        return subnets;
    }

    for (PIP_ADAPTER_ADDRESSES adapter = adapters; adapter != nullptr; adapter = adapter->Next) {
        // 只处理当前处于「已连接」状态的网卡
        if (adapter->OperStatus != IfOperStatusUp) {
            continue;
        }

        for (PIP_ADAPTER_UNICAST_ADDRESS address = adapter->FirstUnicastAddress;
             address != nullptr;
             address = address->Next) {
            if (address->Address.lpSockaddr == nullptr
                || address->Address.lpSockaddr->sa_family != AF_INET) {
                continue;
            }

            const std::string localIp = sockaddrToIpv4(address->Address.lpSockaddr);
            if (localIp.empty() || isLoopbackIp(localIp)) {
                continue;
            }

            const std::string subnetMask = prefixLengthToMask(
                static_cast<int>(address->OnLinkPrefixLength));
            // 首版仅支持 /24，其他掩码（如 /23、/16）跳过
            if (subnetMask != "255.255.255.0") {
                continue;
            }

            LocalSubnet subnet{};
            subnet.adapterName = wideToUtf8(adapter->FriendlyName);
            if (subnet.adapterName.empty()) {
                subnet.adapterName = wideToUtf8(adapter->Description);
            }
            subnet.localIp = localIp;
            subnet.subnetMask = subnetMask;
            if (!buildSlash24ScanRange(localIp, subnet)) {
                continue;
            }

            subnets.push_back(subnet);
        }
    }
#endif

    return subnets;
}
