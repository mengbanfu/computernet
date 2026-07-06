#pragma once

#include <string>
#include <vector>

#include "Scanner.h"

// 将扫描结果写入 TXT 文件（适合人阅读，默认仅含开放端口）
void writeTxt(const std::vector<ScanResult>& results, const std::string& filename);

// 将扫描结果写入 CSV 文件，字段：IP,Port,Status,Service,TimeMs
void writeCsv(const std::vector<ScanResult>& results, const std::string& filename);
