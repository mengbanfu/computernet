#include "BannerGrabber.h"

#include <cstddef>
#include <cstring>

namespace {

// 单次最多读取的字节数，防止异常响应占用过多内存
constexpr size_t kMaxBannerBytes = 512;
// 控制台/报告展示时的最大长度，避免一行过长
constexpr size_t kMaxBannerDisplayLength = 128;

// HTTP 常用端口：这些端口需要先发送 HEAD 请求，再解析响应头
bool isHttpPort(int port) {
    return port == 80 || port == 8080;
}

// 去掉字符串首尾空白字符
std::string trimCopy(const std::string& text) {
    const auto start = text.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) {
        return "";
    }
    const auto end = text.find_last_not_of(" \t\r\n");
    return text.substr(start, end - start + 1);
}

// 将 Banner 压成单行，便于控制台输出和写入报告
std::string toSingleLine(std::string text) {
    for (char& ch : text) {
        if (ch == '\r' || ch == '\n') {
            ch = ' ';
        }
    }
    return trimCopy(text);
}

// 单行化并截断，保证展示长度可控
std::string truncateBanner(std::string text) {
    text = toSingleLine(std::move(text));
    if (text.size() > kMaxBannerDisplayLength) {
        text.resize(kMaxBannerDisplayLength);
    }
    return text;
}

// ----------------------------------------------------------------
// send() 循环：确保整段 HTTP 请求全部发出
// ----------------------------------------------------------------
// TCP 是字节流，一次 send 不一定发完；短请求也需要循环发送剩余部分。
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

// ----------------------------------------------------------------
// recv()：读取服务端返回的前若干字节
// ----------------------------------------------------------------
// 只取一次 recv，足够覆盖 HTTP 响应头或 SSH/FTP 等协议的欢迎 Banner。
std::string recvSome(net::SocketHandle sock) {
    char buffer[kMaxBannerBytes + 1]{};
    const int received = net::recvBytes(sock, buffer, static_cast<int>(kMaxBannerBytes));
    if (received <= 0) {
        return "";
    }
    return std::string(buffer, static_cast<size_t>(received));
}

// 从 HTTP 响应中提取 "Server:" 响应头的值（如 nginx/1.24.0）
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

// 提取 HTTP 响应的第一行（状态行，如 HTTP/1.1 200 OK）
std::string extractFirstLine(const std::string& response) {
    const auto lineEnd = response.find_first_of("\r\n");
    if (lineEnd == std::string::npos) {
        return trimCopy(response);
    }
    return trimCopy(response.substr(0, lineEnd));
}

// 优先返回 Server 头；若无则退化为状态行
std::string parseHttpBanner(const std::string& response) {
    const std::string serverHeader = extractHttpServerHeader(response);
    if (!serverHeader.empty()) {
        return serverHeader;
    }

    // 没有 Server 头时，尝试用状态行作为简要信息
    return extractFirstLine(response);
}

}  // namespace

// ----------------------------------------------------------------
// grabBanner：对已建立 TCP 连接的开放端口尝试获取 Banner
// ----------------------------------------------------------------
// 两种策略：
//   1. HTTP 端口（80/8080）：发送 HEAD / HTTP/1.0，解析响应头
//   2. 其他端口：直接 recv，读取服务端主动推送的欢迎信息（SSH、FTP 等）
//
// 注意：套接字由调用方创建并在 connect 成功后传入；本函数不负责关闭。
std::string grabBanner(net::SocketHandle connectedSocket, int port, int timeoutMs) {
    if (!net::isValidSocket(connectedSocket)) {
        return "";
    }

    // Banner 阶段改回阻塞模式，并设置较短收发超时
    net::setBlocking(connectedSocket, true);
    net::setSendReceiveTimeout(connectedSocket, timeoutMs);

    if (isHttpPort(port)) {
        // HEAD 比 GET 更轻量：只要响应头，不要正文
        static const char kHttpHeadRequest[] = "HEAD / HTTP/1.0\r\n\r\n";
        if (!sendAll(connectedSocket, kHttpHeadRequest,
                     static_cast<int>(sizeof(kHttpHeadRequest) - 1))) {
            return "";
        }

        const std::string response = recvSome(connectedSocket);
        if (response.empty()) {
            return "";
        }

        return truncateBanner(parseHttpBanner(response));
    }

    // 其他协议：连接建立后直接尝试读取服务端主动发送的 Banner（如 SSH、FTP）
    const std::string rawBanner = recvSome(connectedSocket);
    if (rawBanner.empty()) {
        return "";
    }

    return truncateBanner(rawBanner);
}
