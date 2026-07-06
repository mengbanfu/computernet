#pragma once

#include <iostream>
#include <limits>
#include <string>

// 设置控制台为 UTF-8，便于显示中文
void setupConsoleUtf8();

// 清空 cin 中的错误状态和剩余输入
void clearInputStream();

// 读取一行非空文本
std::string readNonEmptyLine(const std::string& prompt);

// 读取一行文本，允许为空
std::string readLine(const std::string& prompt);

// 读取整数，失败或不在 [minValue, maxValue] 内则重新输入
int readIntInRange(const std::string& prompt, int minValue, int maxValue);

// 读取 y/n，返回 true 表示 yes
bool readYesNo(const std::string& prompt);

// 获取当前本地时间字符串，格式：YYYY-MM-DD HH:MM:SS
std::string currentDateTimeString();

// 暂停，等待用户按回车继续
void pauseForEnter();
