/**
 * SimplePortScanner - TCP Connect 端口扫描工具
 */

#include "CliApp.h"
#include "ConsoleUtil.h"
#include "NetCompat.h"

#include <iostream>

int main() {
    setupConsoleUtf8();

    net::NetworkRuntime networkRuntime;
    if (!networkRuntime.ok()) {
        std::cerr << "网络初始化失败" << std::endl;
        return 1;
    }

    CliApp app;
    app.run();

    return 0;
}
