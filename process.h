#include <string>

std::string ExecuteCommand(const char* cmd);

void SaveInfoToFile(const std::string& data, const std::string& filename);

std::string GetCpuUsage();

std::string GetDiskUsage();

std::string GetNetworkUsage();

void SaveAllInfo(const std::string& filename);

int CollectAndSaveResourceUsage();