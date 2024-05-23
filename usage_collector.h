#pragma once

#include <string>
#include "error_codes.h"

class CUsageCollector {
public:
    int RunCommand(const char* pCommand, std::string& strResult);
    int SaveDataToFile(const std::string& strData, const std::string& strFileName);
    int GetCpuUsage(std::string& strResult);
    int GetDiskUsage(std::string& strResult);
    int GetNetworkUsage(std::string& strResult);
    int SaveUsageToFile(const std::string& strFileName);
    int CollectAndSaveUsage();
};