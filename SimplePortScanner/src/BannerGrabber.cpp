#include "BannerGrabber.h"

#include "ServiceDetector.h"

// 兼容旧接口：返回协议探测得到的 Banner 摘要
std::string grabBanner(net::SocketHandle connectedSocket, int port, int timeoutMs) {
    return detectService(connectedSocket, port, timeoutMs).banner;
}
