#pragma once

#include <string>
#include <vector>
#include "util.h"

struct UserData {
    std::vector<std::string>* detectedMalware;
    const std::string* filePath;
};

void StartScan();
void ScanDirectory(const std::string& path, int option);
void MoveDetectedMalware(const std::vector<std::string>& detectedMalware);
bool MoveFile(const std::string& filePath, const std::string& quarantineDir);
