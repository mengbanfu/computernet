cmake_minimum_required(VERSION 3.14)

project(SimplePortScanner VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(SimplePortScanner
    src/main.cpp
    src/CliApp.cpp
    src/ConsoleUtil.cpp
    src/NetCompat.cpp
    src/WebApp.cpp
    src/Scanner.cpp
    src/PortParser.cpp
    src/IpParser.cpp
    src/ServiceMap.cpp
    src/ResultWriter.cpp
    src/BannerGrabber.cpp
)

target_compile_definitions(SimplePortScanner PRIVATE
    SIMPLE_PORT_SCANNER_WEB_ROOT="${CMAKE_CURRENT_SOURCE_DIR}/web"
)

# Winsock2 库，TCP Connect 扫描所需
if(WIN32)
    target_link_libraries(SimplePortScanner PRIVATE ws2_32)
endif()

find_package(Threads REQUIRED)
target_link_libraries(SimplePortScanner PRIVATE Threads::Threads)

# MSVC 默认按 GBK 解析源文件，中文 UTF-8 会导致字符串字面量编译错误
if(MSVC)
    target_compile_options(SimplePortScanner PRIVATE /utf-8)
endif()
