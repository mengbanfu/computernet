#include "NetCompat.h"

#include <algorithm>
#include <cerrno>
#include <cstdint>

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

namespace net {

bool initialize() {
#ifdef _WIN32
    WSADATA wsaData{};
    return WSAStartup(MAKEWORD(2, 2), &wsaData) == 0;
#else
    return true;
#endif
}

void cleanup() {
#ifdef _WIN32
    WSACleanup();
#endif
}

SocketHandle invalidSocket() {
#ifdef _WIN32
    return INVALID_SOCKET;
#else
    return -1;
#endif
}

bool isValidSocket(SocketHandle socket) {
    return socket != invalidSocket();
}

SocketHandle createTcpSocket() {
    return ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
}

void closeSocket(SocketHandle socket) {
    if (!isValidSocket(socket)) {
        return;
    }

#ifdef _WIN32
    closesocket(socket);
#else
    close(socket);
#endif
}

bool setBlocking(SocketHandle socket, bool blocking) {
#ifdef _WIN32
    u_long mode = blocking ? 0UL : 1UL;
    return ioctlsocket(socket, FIONBIO, &mode) == 0;
#else
    const int flags = fcntl(socket, F_GETFL, 0);
    if (flags < 0) {
        return false;
    }

    const int updatedFlags = blocking ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);
    return fcntl(socket, F_SETFL, updatedFlags) == 0;
#endif
}

bool setSendReceiveTimeout(SocketHandle socket, int timeoutMs) {
    const int safeTimeoutMs = std::max(timeoutMs, 0);

#ifdef _WIN32
    const DWORD timeout = static_cast<DWORD>(safeTimeoutMs);
    return setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO,
                      reinterpret_cast<const char*>(&timeout), sizeof(timeout)) == 0
        && setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO,
                      reinterpret_cast<const char*>(&timeout), sizeof(timeout)) == 0;
#else
    timeval timeout{};
    timeout.tv_sec = safeTimeoutMs / 1000;
    timeout.tv_usec = (safeTimeoutMs % 1000) * 1000;
    return setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO,
                      &timeout, sizeof(timeout)) == 0
        && setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO,
                      &timeout, sizeof(timeout)) == 0;
#endif
}

int getLastError() {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

bool isConnectInProgress(int errorCode) {
#ifdef _WIN32
    return errorCode == WSAEWOULDBLOCK
        || errorCode == WSAEINPROGRESS
        || errorCode == WSAEALREADY;
#else
    return errorCode == EINPROGRESS
        || errorCode == EWOULDBLOCK
        || errorCode == EALREADY;
#endif
}

ConnectResult connectTcp(SocketHandle socket, const std::string& ip, int port) {
    sockaddr_in targetAddr{};
    targetAddr.sin_family = AF_INET;
    targetAddr.sin_port = htons(static_cast<uint16_t>(port));

    if (inet_pton(AF_INET, ip.c_str(), &targetAddr.sin_addr) != 1) {
#ifdef _WIN32
        WSASetLastError(WSAEINVAL);
#else
        errno = EINVAL;
#endif
        return ConnectResult::Failed;
    }

    const int result = ::connect(socket,
                                 reinterpret_cast<sockaddr*>(&targetAddr),
                                 sizeof(targetAddr));
    if (result == 0) {
        return ConnectResult::Connected;
    }

    const int errorCode = getLastError();
    if (isConnectInProgress(errorCode)) {
        return ConnectResult::InProgress;
    }

    return ConnectResult::Failed;
}

WaitResult waitForConnect(SocketHandle socket, int timeoutMs) {
    const int safeTimeoutMs = std::max(timeoutMs, 0);

#ifdef _WIN32
    fd_set writeFds;
    fd_set exceptFds;
    FD_ZERO(&writeFds);
    FD_ZERO(&exceptFds);
    FD_SET(socket, &writeFds);
    FD_SET(socket, &exceptFds);

    timeval tv{};
    tv.tv_sec = safeTimeoutMs / 1000;
    tv.tv_usec = (safeTimeoutMs % 1000) * 1000;

    const int selectResult = select(0, nullptr, &writeFds, &exceptFds, &tv);
    if (selectResult == 0) {
        return WaitResult::Timeout;
    }
    if (selectResult == SOCKET_ERROR) {
        return WaitResult::Error;
    }
    return WaitResult::Ready;
#else
    pollfd fd{};
    fd.fd = socket;
    fd.events = POLLOUT;

    const int pollResult = poll(&fd, 1, safeTimeoutMs);
    if (pollResult == 0) {
        return WaitResult::Timeout;
    }
    if (pollResult < 0 || (fd.revents & POLLNVAL) != 0) {
        return WaitResult::Error;
    }
    return WaitResult::Ready;
#endif
}

bool getSocketError(SocketHandle socket, int& errorCode) {
    errorCode = 0;

#ifdef _WIN32
    int optLen = sizeof(errorCode);
    return getsockopt(socket, SOL_SOCKET, SO_ERROR,
                      reinterpret_cast<char*>(&errorCode), &optLen) == 0;
#else
    socklen_t optLen = sizeof(errorCode);
    return getsockopt(socket, SOL_SOCKET, SO_ERROR, &errorCode, &optLen) == 0;
#endif
}

int sendBytes(SocketHandle socket, const char* data, int length) {
#ifdef _WIN32
    return send(socket, data, length, 0);
#else
#ifdef MSG_NOSIGNAL
    return static_cast<int>(send(socket, data, static_cast<size_t>(length), MSG_NOSIGNAL));
#else
    return static_cast<int>(send(socket, data, static_cast<size_t>(length), 0));
#endif
#endif
}

int recvBytes(SocketHandle socket, char* buffer, int length) {
#ifdef _WIN32
    return recv(socket, buffer, length, 0);
#else
    return static_cast<int>(recv(socket, buffer, static_cast<size_t>(length), 0));
#endif
}

NetworkRuntime::NetworkRuntime()
    : ok_(initialize()) {
}

NetworkRuntime::~NetworkRuntime() {
    if (ok_) {
        cleanup();
    }
}

bool NetworkRuntime::ok() const {
    return ok_;
}

SocketGuard::SocketGuard(SocketHandle socket)
    : socket_(socket) {
}

SocketGuard::~SocketGuard() {
    closeSocket(socket_);
}

SocketHandle SocketGuard::get() const {
    return socket_;
}

bool SocketGuard::isValid() const {
    return isValidSocket(socket_);
}

SocketHandle SocketGuard::release() {
    const SocketHandle socket = socket_;
    socket_ = invalidSocket();
    return socket;
}

}  // namespace net
