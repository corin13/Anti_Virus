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
    int GetMemoryUsage(std::string& strResult);
    void ShowProgress(const std::string& message, int progress, int total);
    void DisplayMenu();
    void GetUserChoices(bool& bCollectCpu, bool& bCollectDisk, bool& bCollectNetwork, bool& bCollectMemory);
    int SaveUsageToFile(const std::string& strFileName, bool bCpu, bool bDisk, bool bNetwork, bool bMemory);
    int CollectAndSaveUsage();
    int GetNetworkInterfaces(std::vector<std::string>& interfaces);
};