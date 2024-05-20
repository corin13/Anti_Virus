#pragma once

#include <string>
#include <vector>

struct UserData {
    std::vector<std::string>* detectedMalware;
    const std::string* filePath;
};

void scan();
void scanDirectory(const std::string& path, int option);
void moveDetectedMalware(const std::vector<std::string>& detectedMalware);
bool moveFile(const std::string& filePath, const std::string& quarantineDir);
