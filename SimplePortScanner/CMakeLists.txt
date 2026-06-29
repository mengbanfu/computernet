cmake_minimum_required(VERSION 3.14)

project(SimplePortScanner VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(SimplePortScanner src/main.cpp)

# Winsock2 库，TCP Connect 扫描所需
if(WIN32)
    target_link_libraries(SimplePortScanner PRIVATE ws2_32)
endif()
