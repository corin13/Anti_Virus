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
    static bool m_bStopScanning;

    int StartScan();
    int StartIniScan();

private:
    std::vector<std::string> m_vecDetectedMalware; // 악성파일로 판별된 파일의 경로를 저장
    std::string m_strScanTargetPath;
    int m_nScanTypeOption;
    int m_nFileTypeOption;
    int m_nFileCount;
    long long m_llTotalSize;
    double m_dScanTime;
    std::string m_strExtension;
    std::vector<ST_ScanData> m_vecScanData;

    int PerformFileScan();
    int ScanDirectory();
    int MoveDetectedMalware();
    int MoveFile(ST_ScanData& data, const std::string& quarantineDir);
    int PrintScanResult();
    void LogResult(ST_ScanData& data);
};