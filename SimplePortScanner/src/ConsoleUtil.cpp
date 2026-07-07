#include "ConsoleUtil.h"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

void setupConsoleUtf8() {
#ifdef _WIN32
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
#endif
}

void clearInputStream() {
    std::cin.clear();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

std::string readNonEmptyLine(const std::string& prompt) {
    while (true) {
        std::cout << prompt;
        std::string line;
        if (!std::getline(std::cin, line)) {
            clearInputStream();
            continue;
        }

        if (!line.empty()) {
            return line;
        }

        std::cout << "输入不能为空，请重新输入。" << std::endl;
    }
}

std::string readLine(const std::string& prompt) {
    std::cout << prompt;
    std::string line;
    if (!std::getline(std::cin, line)) {
        clearInputStream();
        return "";
    }
    return line;
}

int readIntInRange(const std::string& prompt, int minValue, int maxValue) {
    while (true) {
        std::cout << prompt;
        std::string line;
        if (!std::getline(std::cin, line)) {
            clearInputStream();
            std::cout << "输入无效，请重新输入。" << std::endl;
            continue;
        }

        try {
            size_t consumed = 0;
            const long long value = std::stoll(line, &consumed);
            if (consumed != line.size()) {
                std::cout << "输入无效，请输入整数。" << std::endl;
                continue;
            }
            if (value < minValue || value > maxValue) {
                std::cout << "请输入 " << minValue << "-" << maxValue << " 之间的整数。" << std::endl;
                continue;
            }
            return static_cast<int>(value);
        } catch (...) {
            std::cout << "输入无效，请重新输入。" << std::endl;
        }
    }
}

bool readYesNo(const std::string& prompt) {
    while (true) {
        std::cout << prompt;
        std::string line;
        if (!std::getline(std::cin, line)) {
            clearInputStream();
            std::cout << "请输入 y 或 n。" << std::endl;
            continue;
        }

        if (line.size() == 1 && (line[0] == 'y' || line[0] == 'Y')) {
            return true;
        }
        if (line.size() == 1 && (line[0] == 'n' || line[0] == 'N')) {
            return false;
        }

        std::cout << "请输入 y 或 n。" << std::endl;
    }
}

std::string currentDateTimeString() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t timeValue = std::chrono::system_clock::to_time_t(now);

    std::tm localTime{};
#ifdef _WIN32
    localtime_s(&localTime, &timeValue);
#else
    localtime_r(&timeValue, &localTime);
#endif

    std::ostringstream output;
    output << std::put_time(&localTime, "%Y-%m-%d %H:%M:%S");
    return output.str();
}

void pauseForEnter() {
    std::cout << std::endl << "按回车键返回菜单...";
    std::string line;
    std::getline(std::cin, line);
}
