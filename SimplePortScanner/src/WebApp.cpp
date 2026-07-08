#include "WebApp.h"

#include "IpParser.h"
#include "NetCompat.h"
#include "PortParser.h"
#include "Scanner.h"
#include "ServiceMap.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#ifndef SIMPLE_PORT_SCANNER_WEB_ROOT
#define SIMPLE_PORT_SCANNER_WEB_ROOT "web"
#endif

namespace {

struct HttpRequest {
    std::string method;
    std::string path;
    std::string body;
};

struct ScanRequest {
    std::string ipExpression;
    std::string portExpression;
    int timeoutMs = 500;
    int threadCount = 10;
};

std::string webRoot() {
    return SIMPLE_PORT_SCANNER_WEB_ROOT;
}

std::string trim(const std::string& text) {
    const auto start = text.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) {
        return "";
    }
    const auto end = text.find_last_not_of(" \t\r\n");
    return text.substr(start, end - start + 1);
}

std::string readTextFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("file not found");
    }

    std::ostringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

std::string jsonEscape(const std::string& value) {
    std::string output;
    output.reserve(value.size() + 8);

    for (unsigned char ch : value) {
        switch (ch) {
            case '\\':
                output += "\\\\";
                break;
            case '"':
                output += "\\\"";
                break;
            case '\n':
                output += "\\n";
                break;
            case '\r':
                output += "\\r";
                break;
            case '\t':
                output += "\\t";
                break;
            default:
                if (ch < 0x20) {
                    output += ' ';
                } else {
                    output += static_cast<char>(ch);
                }
                break;
        }
    }

    return output;
}

std::string httpStatusText(int statusCode) {
    switch (statusCode) {
        case 200:
            return "OK";
        case 400:
            return "Bad Request";
        case 404:
            return "Not Found";
        case 500:
            return "Internal Server Error";
        default:
            return "OK";
    }
}

std::string buildResponse(int statusCode,
                          const std::string& contentType,
                          const std::string& body) {
    std::ostringstream response;
    response << "HTTP/1.1 " << statusCode << ' ' << httpStatusText(statusCode) << "\r\n";
    response << "Content-Type: " << contentType << "\r\n";
    response << "Content-Length: " << body.size() << "\r\n";
    response << "Connection: close\r\n";
    response << "X-Content-Type-Options: nosniff\r\n";
    response << "\r\n";
    response << body;
    return response.str();
}

std::string jsonError(const std::string& message) {
    return "{\"ok\":false,\"error\":\"" + jsonEscape(message) + "\"}";
}

bool sendAll(net::SocketHandle client, const std::string& data) {
    const char* current = data.data();
    int remaining = static_cast<int>(data.size());

    while (remaining > 0) {
        const int sent = net::sendBytes(client, current, remaining);
        if (sent <= 0) {
            return false;
        }
        current += sent;
        remaining -= sent;
    }

    return true;
}

int parseContentLength(const std::string& headers) {
    std::istringstream stream(headers);
    std::string line;
    while (std::getline(stream, line)) {
        const std::string prefix = "Content-Length:";
        if (line.size() >= prefix.size()) {
            std::string name = line.substr(0, prefix.size());
            std::transform(name.begin(), name.end(), name.begin(),
                           [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
            if (name == "content-length:") {
                return std::max(0, std::atoi(trim(line.substr(prefix.size())).c_str()));
            }
        }
    }
    return 0;
}

bool readHttpRequest(net::SocketHandle client, HttpRequest& request) {
    std::string raw;
    char buffer[4096];

    while (raw.find("\r\n\r\n") == std::string::npos) {
        const int received = net::recvBytes(client, buffer, sizeof(buffer));
        if (received <= 0) {
            return false;
        }
        raw.append(buffer, buffer + received);
        if (raw.size() > 1024 * 1024) {
            return false;
        }
    }

    const size_t headerEnd = raw.find("\r\n\r\n");
    const std::string headerBlock = raw.substr(0, headerEnd);
    const int contentLength = parseContentLength(headerBlock);

    while (raw.size() < headerEnd + 4 + static_cast<size_t>(contentLength)) {
        const int received = net::recvBytes(client, buffer, sizeof(buffer));
        if (received <= 0) {
            return false;
        }
        raw.append(buffer, buffer + received);
        if (raw.size() > 1024 * 1024) {
            return false;
        }
    }

    std::istringstream firstLineStream(headerBlock);
    firstLineStream >> request.method >> request.path;
    request.body = raw.substr(headerEnd + 4, static_cast<size_t>(contentLength));
    return !request.method.empty() && !request.path.empty();
}

bool extractJsonString(const std::string& json, const std::string& key, std::string& value) {
    const std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) {
        return false;
    }
    pos = json.find(':', pos + needle.size());
    if (pos == std::string::npos) {
        return false;
    }
    pos = json.find('"', pos + 1);
    if (pos == std::string::npos) {
        return false;
    }

    std::string result;
    bool escaped = false;
    for (size_t i = pos + 1; i < json.size(); ++i) {
        const char ch = json[i];
        if (escaped) {
            switch (ch) {
                case 'n':
                    result += '\n';
                    break;
                case 'r':
                    result += '\r';
                    break;
                case 't':
                    result += '\t';
                    break;
                default:
                    result += ch;
                    break;
            }
            escaped = false;
            continue;
        }
        if (ch == '\\') {
            escaped = true;
            continue;
        }
        if (ch == '"') {
            value = result;
            return true;
        }
        result += ch;
    }

    return false;
}

bool extractJsonInt(const std::string& json, const std::string& key, int& value) {
    const std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) {
        return false;
    }
    pos = json.find(':', pos + needle.size());
    if (pos == std::string::npos) {
        return false;
    }
    ++pos;
    while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos]))) {
        ++pos;
    }

    size_t end = pos;
    while (end < json.size() && (std::isdigit(static_cast<unsigned char>(json[end])) || json[end] == '-')) {
        ++end;
    }
    if (end == pos) {
        return false;
    }

    value = std::atoi(json.substr(pos, end - pos).c_str());
    return true;
}

bool parseScanRequest(const std::string& body, ScanRequest& request, std::string& error) {
    if (!extractJsonString(body, "ipExpression", request.ipExpression)
        || trim(request.ipExpression).empty()) {
        error = "IP expression is required.";
        return false;
    }
    if (!extractJsonString(body, "portExpression", request.portExpression)
        || trim(request.portExpression).empty()) {
        error = "Port expression is required.";
        return false;
    }
    if (!extractJsonInt(body, "timeoutMs", request.timeoutMs) || request.timeoutMs < 1) {
        error = "Timeout must be a positive integer.";
        return false;
    }
    if (!extractJsonInt(body, "threadCount", request.threadCount) || request.threadCount < 1) {
        error = "Thread count must be a positive integer.";
        return false;
    }
    return true;
}

std::string servicesJson() {
    std::ostringstream json;
    json << "{\"services\":[";

    const std::vector<ServiceEntry> services = getKnownServices();
    for (size_t i = 0; i < services.size(); ++i) {
        if (i > 0) {
            json << ',';
        }
        json << "{\"port\":" << services[i].port
             << ",\"name\":\"" << jsonEscape(services[i].name) << "\"}";
    }

    json << "]}";
    return json.str();
}

std::string scanJson(const ScanRequest& request) {
    std::string parseError;
    const std::vector<std::string> ips = parseIPs(request.ipExpression, parseError);
    if (ips.empty()) {
        return jsonError("Invalid IP expression: " + parseError);
    }

    const std::vector<int> ports = parsePorts(request.portExpression, parseError);
    if (ports.empty()) {
        return jsonError("Invalid port expression: " + parseError);
    }

    std::vector<ScanResult> openResults;
    const RangeScanSummary summary = scanTargetsConcurrent(
        ips,
        ports,
        request.timeoutMs,
        request.threadCount,
        &openResults,
        false);

    std::ostringstream json;
    json << "{\"ok\":true";
    json << ",\"summary\":{";
    json << "\"hostCount\":" << summary.hostCount;
    json << ",\"portCount\":" << summary.portCount;
    json << ",\"totalTasks\":" << summary.totalTasks;
    json << ",\"openPorts\":" << summary.openPorts;
    json << ",\"closedPorts\":" << summary.closedPorts;
    json << ",\"timeoutPorts\":" << summary.timeoutPorts;
    json << ",\"elapsedSeconds\":" << summary.elapsedSeconds;
    json << "},\"openResults\":[";

    for (size_t i = 0; i < openResults.size(); ++i) {
        const ScanResult& result = openResults[i];
        if (i > 0) {
            json << ',';
        }
        json << "{\"ip\":\"" << jsonEscape(result.ip) << "\"";
        json << ",\"port\":" << result.port;
        json << ",\"service\":\"" << jsonEscape(getServiceName(result.port)) << "\"";
        json << ",\"timeMs\":" << result.timeMs;
        json << ",\"banner\":\"" << jsonEscape(result.banner) << "\"}";
    }

    json << "]}";
    return json.str();
}

std::string staticContentType(const std::string& path) {
    if (path == "/styles.css") {
        return "text/css; charset=utf-8";
    }
    if (path == "/app.js") {
        return "application/javascript; charset=utf-8";
    }
    return "text/html; charset=utf-8";
}

std::string handleRequest(const HttpRequest& request) {
    try {
        if (request.method == "GET" && request.path == "/") {
            return buildResponse(200, staticContentType("/"), readTextFile(webRoot() + "/v2.html"));
        }
        if (request.method == "GET" && (request.path == "/styles.css" || request.path == "/app.js")) {
            const std::string filename = request.path == "/styles.css" ? "/v2-poster.css" : "/v2-poster.js";
            return buildResponse(200, staticContentType(request.path), readTextFile(webRoot() + filename));
        }
        if (request.method == "GET" && request.path == "/api/services") {
            return buildResponse(200, "application/json; charset=utf-8", servicesJson());
        }
        if (request.method == "POST" && request.path == "/api/scan") {
            ScanRequest scanRequest;
            std::string error;
            if (!parseScanRequest(request.body, scanRequest, error)) {
                return buildResponse(400, "application/json; charset=utf-8", jsonError(error));
            }

            const std::string body = scanJson(scanRequest);
            const int status = body.find("\"ok\":false") == std::string::npos ? 200 : 400;
            return buildResponse(status, "application/json; charset=utf-8", body);
        }
    } catch (const std::exception& ex) {
        return buildResponse(500, "application/json; charset=utf-8", jsonError(ex.what()));
    }

    return buildResponse(404, "text/plain; charset=utf-8", "Not found");
}

net::SocketHandle createListenSocket(int port) {
    net::SocketHandle server = net::createTcpSocket();
    if (!net::isValidSocket(server)) {
        return net::invalidSocket();
    }

    int reuse = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(static_cast<unsigned short>(port));
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);

    if (bind(server, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        net::closeSocket(server);
        return net::invalidSocket();
    }

    if (listen(server, 16) != 0) {
        net::closeSocket(server);
        return net::invalidSocket();
    }

    return server;
}

}  // namespace

WebApp::WebApp(int port)
    : port_(port) {
}

int WebApp::run() {
    net::SocketGuard server(createListenSocket(port_));
    if (!server.isValid()) {
        std::cerr << "Failed to start web server on http://127.0.0.1:" << port_ << std::endl;
        return 1;
    }

    std::cout << "SimplePortScanner web UI: http://127.0.0.1:" << port_ << std::endl;
    std::cout << "Press Ctrl+C to stop." << std::endl;

    while (true) {
        sockaddr_in clientAddress{};
#ifdef _WIN32
        int clientAddressLength = sizeof(clientAddress);
#else
        socklen_t clientAddressLength = sizeof(clientAddress);
#endif
        net::SocketHandle client = accept(server.get(),
                                          reinterpret_cast<sockaddr*>(&clientAddress),
                                          &clientAddressLength);
        if (!net::isValidSocket(client)) {
            continue;
        }

        net::SocketGuard clientGuard(client);
        HttpRequest request;
        if (!readHttpRequest(clientGuard.get(), request)) {
            continue;
        }

        sendAll(clientGuard.get(), handleRequest(request));
    }

    return 0;
}
