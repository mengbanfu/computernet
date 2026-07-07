#pragma once

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#endif

#include <string>

namespace net {

#ifdef _WIN32
using SocketHandle = SOCKET;
#else
using SocketHandle = int;
#endif

enum class ConnectResult {
    Connected,
    InProgress,
    Failed
};

enum class WaitResult {
    Ready,
    Timeout,
    Error
};

bool initialize();
void cleanup();

SocketHandle invalidSocket();
bool isValidSocket(SocketHandle socket);
SocketHandle createTcpSocket();
void closeSocket(SocketHandle socket);

bool setBlocking(SocketHandle socket, bool blocking);
bool setSendReceiveTimeout(SocketHandle socket, int timeoutMs);

int getLastError();
bool isConnectInProgress(int errorCode);

ConnectResult connectTcp(SocketHandle socket, const std::string& ip, int port);
WaitResult waitForConnect(SocketHandle socket, int timeoutMs);
bool getSocketError(SocketHandle socket, int& errorCode);

int sendBytes(SocketHandle socket, const char* data, int length);
int recvBytes(SocketHandle socket, char* buffer, int length);

class NetworkRuntime {
public:
    NetworkRuntime();
    ~NetworkRuntime();

    bool ok() const;

private:
    bool ok_ = false;
};

class SocketGuard {
public:
    explicit SocketGuard(SocketHandle socket);
    ~SocketGuard();

    SocketGuard(const SocketGuard&) = delete;
    SocketGuard& operator=(const SocketGuard&) = delete;

    SocketHandle get() const;
    bool isValid() const;
    SocketHandle release();

private:
    SocketHandle socket_;
};

}  // namespace net
