#pragma once

#include <string>
#include <vector>
#include "util.h"

#define ALL_FILES 1
#define ELF_FILES 2
#define SPECIFIC_EXTENSION 3

#define YARA_RULE 1
#define HASH_COMPARISON 2

#define DEFAULT_PATH "./"
#define DEFAULT_EXTENSION "exe"

#define YARA_RULES_PATH "yara-rules"
#define HASH_LIST_PATH "hashes.txt"
#define DESTINATION_PATH "detected-malware"
#define LOG_FILE_PATH "logs/file_scanner.log"

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

    CFileScanner();
    CFileScanner(const std::string& logFilePath);
    CFileScanner(int scanTypeOption, int fileTypeOption, const std::string& logFilePath);
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
    std::string m_strLogFilePath;

    int PerformFileScan();
    int ScanDirectory();
    int MoveDetectedMalware();
    int MoveFile(ST_ScanData& data, const std::string& quarantineDir);
    int PrintScanResult();
    void LogResult(ST_ScanData& data);
};