// ----------------------------------------------------------------
// ServiceDetector - 协议探测式服务识别
// ----------------------------------------------------------------
// Connect 扫描只能判断端口开/关；本模块在 TCP 连接建立后，
// 按协议发送探测包或读取 Banner，根据响应特征识别实际服务。
//
// 识别策略（三层，准确度递减）：
//   1. probe      - 主动/被动协议探测成功（HTTP HEAD、TLS ClientHello 等）
//   2. banner     - 收到响应但需从 Banner 关键词推断
//   3. port-guess - 探测失败，回退到静态端口表（ServiceMap）
//
// 注意：端口号仅用于选择探测顺序（启发式），最终判定依赖协议特征字节。

#include "ServiceDetector.h"

#include "ServiceMap.h"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>

namespace {

// 单次探测最多读取的字节数
constexpr size_t kMaxProbeBytes = 512;
// 控制台/报告展示时的最大 Banner 长度
constexpr size_t kMaxBannerDisplayLength = 128;

// 探测类型：每种对应一种协议交互方式
enum class ProbeKind {
    PassiveRecv,     // 被动读取（SSH/FTP 等服务端主动发 Banner）
    HttpHead,        // 主动发 HTTP HEAD 请求
    TlsClientHello,  // 主动发 TLS 握手，检测 HTTPS
    RedisPing,       // 主动发 Redis PING 命令
    SmtpEhlo         // 读 220  greeting 后发 EHLO
};

// 去掉字符串首尾空白
std::string trimCopy(const std::string& text) {
    const auto start = text.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) {
        return "";
    }
    const auto end = text.find_last_not_of(" \t\r\n");
    return text.substr(start, end - start + 1);
}

// 将多行 Banner 压成单行，便于输出
std::string toSingleLine(std::string text) {
    for (char& ch : text) {
        if (ch == '\r' || ch == '\n') {
            ch = ' ';
        }
    }
    return trimCopy(text);
}

// 单行化并截断，避免一行过长
std::string truncateBanner(std::string text) {
    text = toSingleLine(std::move(text));
    if (text.size() > kMaxBannerDisplayLength) {
        text.resize(kMaxBannerDisplayLength);
    }
    return text;
}

bool containsIgnoreCase(const std::string& haystack, const std::string& needle) {
    if (needle.empty()) {
        return true;
    }
    auto it = std::search(
        haystack.begin(), haystack.end(),
        needle.begin(), needle.end(),
        [](char left, char right) {
            return std::tolower(static_cast<unsigned char>(left)) ==
                   std::tolower(static_cast<unsigned char>(right));
        });
    return it != haystack.end();
}

bool startsWith(const std::string& text, const std::string& prefix) {
    return text.size() >= prefix.size() &&
           text.compare(0, prefix.size(), prefix) == 0;
}

// ----------------------------------------------------------------
// sendAll：循环 send，确保探测包完整发出
// ----------------------------------------------------------------
bool sendAll(net::SocketHandle sock, const char* data, int length) {
    int sentTotal = 0;
    while (sentTotal < length) {
        const int sent = net::sendBytes(sock, data + sentTotal, length - sentTotal);
        if (sent <= 0) {
            return false;
        }
        sentTotal += sent;
    }
    return true;
}

bool sendAll(net::SocketHandle sock, const unsigned char* data, int length) {
    return sendAll(sock, reinterpret_cast<const char*>(data), length);
}

// 读取服务端返回的前若干字节（一次 recv 足够覆盖响应头或欢迎 Banner）
std::string recvSome(net::SocketHandle sock) {
    char buffer[kMaxProbeBytes + 1]{};
    const int received = net::recvBytes(sock, buffer, static_cast<int>(kMaxProbeBytes));
    if (received <= 0) {
        return "";
    }
    return std::string(buffer, static_cast<size_t>(received));
}

// 从 HTTP 响应中提取 "Server:" 头（如 nginx/1.24.0）
std::string extractHttpServerHeader(const std::string& response) {
    const std::string marker = "Server:";
    const auto pos = response.find(marker);
    if (pos == std::string::npos) {
        return "";
    }

    const auto lineEnd = response.find_first_of("\r\n", pos);
    const std::string line = response.substr(
        pos + marker.size(),
        lineEnd == std::string::npos ? std::string::npos : lineEnd - pos - marker.size());

    return trimCopy(line);
}

// 提取 HTTP 响应第一行（状态行，如 HTTP/1.1 200 OK）
std::string extractFirstLine(const std::string& response) {
    const auto lineEnd = response.find_first_of("\r\n");
    if (lineEnd == std::string::npos) {
        return trimCopy(response);
    }
    return trimCopy(response.substr(0, lineEnd));
}

// ----------------------------------------------------------------
// isTlsRecord：判断是否为 TLS 记录头
// ----------------------------------------------------------------
// TLS 记录格式：第 1 字节 0x16 = Handshake，第 2 字节 0x03 = TLS 版本主号
bool isTlsRecord(const std::string& response) {
    if (response.size() < 2) {
        return false;
    }
    const unsigned char type = static_cast<unsigned char>(response[0]);
    const unsigned char major = static_cast<unsigned char>(response[1]);
    return type == 0x16 && (major == 0x03 || major == 0x02 || major == 0x01);
}

ServiceDetection makeDetection(const std::string& name,
                               const std::string& version,
                               const std::string& banner,
                               const std::string& method) {
    ServiceDetection detection{};
    detection.name = name;
    detection.version = version;
    detection.banner = truncateBanner(banner);
    detection.method = method;
    return detection;
}

// ----------------------------------------------------------------
// classifyFromText：根据响应文本特征识别协议类型
// ----------------------------------------------------------------
// 这是"功能判断"的核心：不看端口号，只看字节/文本是否符合某协议特征。
ServiceDetection classifyFromText(const std::string& text) {
    if (text.empty()) {
        return {};
    }

    const std::string firstLine = extractFirstLine(text);

    // SSH：服务端连接后立即发送 "SSH-2.0-OpenSSH_8.9" 等形式
    if (startsWith(firstLine, "SSH-")) {
        std::string version;
        const auto dashPos = firstLine.find('-', 4);
        if (dashPos != std::string::npos && dashPos + 1 < firstLine.size()) {
            version = trimCopy(firstLine.substr(dashPos + 1));
        }
        return makeDetection("SSH", version, text, "probe");
    }

    // FTP/SMTP：均以 220 开头；含 FTP 关键字则判为 FTP，否则 SMTP
    if (startsWith(firstLine, "220")) {
        if (containsIgnoreCase(firstLine, "FTP")) {
            return makeDetection("FTP", "", text, "probe");
        }
        return makeDetection("SMTP", "", text, "probe");
    }

    // HTTP：响应含 "HTTP/1.x" 状态行或响应头
    if (containsIgnoreCase(text, "HTTP/1.")) {
        const std::string serverHeader = extractHttpServerHeader(text);
        return makeDetection("HTTP", serverHeader, text, "probe");
    }

    // Redis：对 PING 命令的回复为 "+PONG"
    if (startsWith(trimCopy(text), "+PONG")) {
        return makeDetection("Redis", "", text, "probe");
    }

    // HTTPS：TLS Handshake 记录（0x16 0x03 ...）
    if (isTlsRecord(text)) {
        return makeDetection("HTTPS", "", text, "probe");
    }

    // 有响应但无法匹配已知协议，留 banner 供后续推断
    return makeDetection("", "", text, "banner");
}

// ----------------------------------------------------------------
// probePassiveRecv：被动读取 Banner
// ----------------------------------------------------------------
// 适用于 SSH、FTP 等"连接建立后服务端先发欢迎信息"的协议。
ServiceDetection probePassiveRecv(net::SocketHandle sock) {
    const std::string response = recvSome(sock);
    if (response.empty()) {
        return {};
    }

    ServiceDetection detected = classifyFromText(response);
    if (!detected.name.empty()) {
        detected.method = "probe";
        detected.banner = truncateBanner(response);
        return detected;
    }

    detected.banner = truncateBanner(response);
    detected.method = "banner";
    return detected;
}

// ----------------------------------------------------------------
// probeHttpHead：主动发送 HTTP HEAD 请求
// ----------------------------------------------------------------
// HEAD 比 GET 更轻量：只要响应头，不要正文。
ServiceDetection probeHttpHead(net::SocketHandle sock) {
    static const char kHttpHeadRequest[] = "HEAD / HTTP/1.0\r\n\r\n";
    if (!sendAll(sock, kHttpHeadRequest, static_cast<int>(sizeof(kHttpHeadRequest) - 1))) {
        return {};
    }

    const std::string response = recvSome(sock);
    if (response.empty() || !containsIgnoreCase(response, "HTTP/1.")) {
        return {};
    }

    const std::string serverHeader = extractHttpServerHeader(response);
    const std::string banner = serverHeader.empty() ? extractFirstLine(response) : serverHeader;
    return makeDetection("HTTP", serverHeader, banner.empty() ? response : banner, "probe");
}

// ----------------------------------------------------------------
// probeTlsClientHello：发送最小 TLS ClientHello 探测 HTTPS
// ----------------------------------------------------------------
// 不需要 OpenSSL：发送固定握手模板，检查是否收到 TLS 记录即可。
// 443 端口上若跑的是明文 HTTP，此探测会失败（符合预期）。
ServiceDetection probeTlsClientHello(net::SocketHandle sock) {
    static const unsigned char kTlsClientHello[] = {
        0x16, 0x03, 0x01, 0x00, 0x4a,  // TLS record: Handshake, TLS 1.0
        0x01, 0x00, 0x00, 0x46,        // ClientHello
        0x03, 0x03,                    // 客户端支持 TLS 1.2
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,                          // session id length = 0
        0x00, 0x02, 0x00, 0x2f,        // 一个 cipher suite
        0x01, 0x00                     // compression + extensions length
    };

    if (!sendAll(sock, kTlsClientHello, static_cast<int>(sizeof(kTlsClientHello)))) {
        return {};
    }

    const std::string response = recvSome(sock);
    if (!isTlsRecord(response)) {
        return {};
    }

    return makeDetection("HTTPS", "", response, "probe");
}

// ----------------------------------------------------------------
// probeRedisPing：发送 Redis PING 命令
// ----------------------------------------------------------------
// Redis 协议为 RESP：PING 正常回复 "+PONG\r\n"
ServiceDetection probeRedisPing(net::SocketHandle sock) {
    static const char kRedisPing[] = "PING\r\n";
    if (!sendAll(sock, kRedisPing, static_cast<int>(sizeof(kRedisPing) - 1))) {
        return {};
    }

    const std::string response = recvSome(sock);
    if (!startsWith(trimCopy(response), "+PONG")) {
        return {};
    }

    return makeDetection("Redis", "", response, "probe");
}

// ----------------------------------------------------------------
// probeSmtpEhlo：SMTP 问候 + EHLO 探测
// ----------------------------------------------------------------
// SMTP 连接后服务端先发 "220 ..."，再发 EHLO 可进一步确认。
ServiceDetection probeSmtpEhlo(net::SocketHandle sock) {
    const std::string greeting = recvSome(sock);
    if (!startsWith(extractFirstLine(greeting), "220")) {
        return {};
    }

    static const char kEhlo[] = "EHLO scanner.local\r\n";
    if (!sendAll(sock, kEhlo, static_cast<int>(sizeof(kEhlo) - 1))) {
        if (!greeting.empty()) {
            return makeDetection("SMTP", "", greeting, "probe");
        }
        return {};
    }

    const std::string response = recvSome(sock);
    const std::string combined = greeting + response;
    if (startsWith(extractFirstLine(greeting), "220")) {
        return makeDetection("SMTP", "", combined, "probe");
    }
    return {};
}

// 根据 ProbeKind 分发到具体探测函数
ServiceDetection runProbe(net::SocketHandle sock, ProbeKind kind) {
    switch (kind) {
        case ProbeKind::PassiveRecv:
            return probePassiveRecv(sock);
        case ProbeKind::HttpHead:
            return probeHttpHead(sock);
        case ProbeKind::TlsClientHello:
            return probeTlsClientHello(sock);
        case ProbeKind::RedisPing:
            return probeRedisPing(sock);
        case ProbeKind::SmtpEhlo:
            return probeSmtpEhlo(sock);
    }
    return {};
}

bool isHttpHintPort(int port) {
    return port == 80 || port == 8080 || port == 8000 || port == 8888;
}

bool isTlsHintPort(int port) {
    return port == 443 || port == 8443;
}

// ----------------------------------------------------------------
// buildProbeOrder：按端口号选择探测顺序（启发式，非最终判定）
// ----------------------------------------------------------------
// 端口号只决定"先试哪种探测"，避免对 SSH 端口发 HTTP 请求等无效操作。
// 非标准端口（如 9000 上的 HTTP）会走默认顺序：PassiveRecv → HttpHead。
std::vector<ProbeKind> buildProbeOrder(int port) {
    if (isTlsHintPort(port)) {
        return {ProbeKind::TlsClientHello};
    }
    if (isHttpHintPort(port)) {
        return {ProbeKind::HttpHead, ProbeKind::PassiveRecv};
    }
    if (port == 6379) {
        return {ProbeKind::RedisPing, ProbeKind::PassiveRecv};
    }
    if (port == 25 || port == 587) {
        return {ProbeKind::SmtpEhlo, ProbeKind::PassiveRecv};
    }
    if (port == 21) {
        return {ProbeKind::PassiveRecv};
    }
    if (port == 22) {
        return {ProbeKind::PassiveRecv};
    }

    // 未知端口：先被动读 Banner，再试 HTTP（可识别非标准端口的 Web 服务）
    return {ProbeKind::PassiveRecv, ProbeKind::HttpHead};
}

// 从已有 Banner 文本二次推断服务名（method = banner）
ServiceDetection inferNameFromBanner(const std::string& banner) {
    ServiceDetection detected = classifyFromText(banner);
    if (!detected.name.empty()) {
        detected.method = "banner";
        return detected;
    }
    if (!detected.banner.empty()) {
        detected.method = "banner";
    }
    return detected;
}

// 最终回退：查静态端口表（method = port-guess，准确度最低）
ServiceDetection fallbackPortGuess(int port) {
    const std::string guessed = getServiceName(port);
    if (guessed == "Unknown") {
        return makeDetection("Unknown", "", "", "port-guess");
    }
    return makeDetection(guessed, "", "", "port-guess");
}

}  // namespace

// 展示时优先用探测结果，否则用端口表猜测
std::string getDisplayServiceName(const ScanResult& result) {
    if (!result.detectedService.empty()) {
        return result.detectedService;
    }
    return getServiceName(result.port);
}

// ----------------------------------------------------------------
// detectService：对已建立 TCP 连接的开放端口执行协议探测
// ----------------------------------------------------------------
// 调用时机：Scanner.cpp 中 connect 成功且判定为 Open 之后。
// 套接字由调用方管理，本函数不负责 closesocket。
ServiceDetection detectService(net::SocketHandle connectedSocket, int port, int timeoutMs) {
    if (!net::isValidSocket(connectedSocket)) {
        return fallbackPortGuess(port);
    }

    // 扫描阶段 socket 为非阻塞；探测阶段改回阻塞 + 短超时
    net::setBlocking(connectedSocket, true);
    net::setSendReceiveTimeout(connectedSocket, timeoutMs);

    const std::vector<ProbeKind> probeOrder = buildProbeOrder(port);
    std::string collectedBanner;

    // 按顺序尝试探测，任一成功即返回
    for (ProbeKind kind : probeOrder) {
        const ServiceDetection detected = runProbe(connectedSocket, kind);
        if (!detected.banner.empty() && collectedBanner.empty()) {
            collectedBanner = detected.banner;
        }
        if (!detected.name.empty()) {
            return detected;
        }
    }

    // 探测未识别出协议，但收到了 Banner → 二次推断
    if (!collectedBanner.empty()) {
        const ServiceDetection inferred = inferNameFromBanner(collectedBanner);
        if (!inferred.name.empty()) {
            return inferred;
        }
        return makeDetection("Unknown", "", collectedBanner, "banner");
    }

    // 完全无响应 → 回退端口表
    return fallbackPortGuess(port);
}
