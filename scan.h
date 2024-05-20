#pragma once

#include <string>
#include <vector>

using namespace std;

struct UserData {
    std::vector<std::string>* detectedMalware;
    const std::string* filePath;
};

void scan();
bool isDirectory(const std::string& path);
void scanDirectory(const std::string& path, int option);
std::vector<std::string> loadHashes(const std::string& filename);
void printError(const std::string& message);
void quarantineDetectedMalware(const std::vector<std::string>& detectedMalware);
bool quarantineFile(const std::string& filePath, const std::string& quarantineDir);
