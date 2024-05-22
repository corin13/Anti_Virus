#pragma once

#include <string>
#include <vector>
#include "util.h"

struct UserData {
    std::vector<std::string>* detectedMalware;
    const std::string* filePath;
};

struct ScanData {
    std::vector<std::string> detectedMalware; // 악성파일로 판별된 파일의 경로를 저장
    const std::string filePath;
    int fileCount;
    long long totalSize;
    double scanTime;
};

void StartScan();
void ScanDirectory(ScanData& scanData, int scanTypeOption, int fileTypeOption, std::string& extension);
void MoveDetectedMalware(const std::vector<std::string>& detectedMalware);
bool MoveFile(const std::string& filePath, const std::string& quarantineDir);
void PrintScanResult(const ScanData& scanData);