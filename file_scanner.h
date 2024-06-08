#pragma once

#include <string>
#include <vector>
#include "util.h"

struct ST_ScanData {
    std::string DetectedFile;
    std::string ScanType;
    std::string YaraRule;
    std::string HashValue;
    std::string FileSize;
    std::string Timestamp;
    bool IsMoved;
    std::string PathAfterMoving;
};

class CFileScanner {
public:
    int StartScan();
    int StartIniScan();
    static bool g_stopScanning;
private:
    std::vector<std::string> m_detectedMalware; // 악성파일로 판별된 파일의 경로를 저장
    std::string m_scanTargetPath;
    int m_scanTypeOption;
    int m_fileTypeOption;
    int m_fileCount;
    long long m_totalSize;
    double m_scanTime;
    std::string m_extension;
    std::vector<ST_ScanData> m_vecScanData;

    int PerformFileScan();
    int ScanDirectory();
    int MoveDetectedMalware();
    int MoveFile(ST_ScanData& data, const std::string& quarantineDir);
    int PrintScanResult();
    void LogResult(ST_ScanData& data);
};