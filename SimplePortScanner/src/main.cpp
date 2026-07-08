/**
 * SimplePortScanner - TCP Connect 端口扫描工具
 */

#include "CliApp.h"
#include "ConsoleUtil.h"
#include "NetCompat.h"
#include "WebApp.h"

#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    setupConsoleUtf8();

    net::NetworkRuntime networkRuntime;
    if (!networkRuntime.ok()) {
        std::cerr << "网络初始化失败" << std::endl;
        return 1;
    }

    if (argc > 1 && std::string(argv[1]) == "--web") {
        WebApp app;
        return app.run();
    }

    CliApp app;
    app.run();

    return 0;
}
