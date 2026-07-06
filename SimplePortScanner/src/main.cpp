/**
 * SimplePortScanner - TCP Connect 端口扫描工具
 */

#include "CliApp.h"
#include "ConsoleUtil.h"

#include <iostream>

#include <winsock2.h>

int main() {
    setupConsoleUtf8();

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup 失败" << std::endl;
        return 1;
    }

    CliApp app;
    app.run();

    WSACleanup();
    return 0;
}
