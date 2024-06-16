#pragma once

#include <string>
#include "ansi_color.h"
#include "error_codes.h"

#define BUFFER_SIZE 128

class CUsageCollector {
public:
    int RunCommand(const char* pCommand, std::string& strResult);
    int SaveDataToFile(const std::string& strData, const std::string& strFileName);
    int GetCpuUsage(std::string& strResult);
    int GetDiskUsage(std::string& strResult);
    int GetNetworkUsage(std::string& strResult);
    int SaveUsageToFile(const std::string& strFileName, bool cpu, bool disk, bool network);
    int CollectAndSaveUsage();
    int GetNetworkInterfaces(std::vector<std::string>& interfaces);
};