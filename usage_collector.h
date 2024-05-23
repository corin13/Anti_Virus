#pragma once

#include <string>

class CUsageCollector {
public:
    std::string RunCommand (const char* command);
    void SaveDataToFile (const std::string& strData, const std::string& strFileName);
    std::string GetCpuUsage();
    std::string GetDiskUsage();
    std::string GetNetworkUsage();
    void SaveUsageToFile (const std::string& strFileName);
    int CollectAndSaveUsage();
};