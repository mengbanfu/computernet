#pragma once

#include "NetCompat.h"
#include "Scanner.h"

// 对已建立 TCP 连接的开放端口执行协议探测，识别实际服务
ServiceDetection detectService(net::SocketHandle connectedSocket, int port, int timeoutMs = 1000);
