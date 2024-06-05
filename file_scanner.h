#pragma once

#include <string>
#include <vector>
#include "util.h"

class CFileScanner {
    public:
        int StartScan(); 
    private:
        std::vector<std::string> m_detectedMalware; // 악성파일로 판별된 파일의 경로를 저장
        std::string m_scanTargetPath;
        int m_scanTypeOption;
        int m_fileTypeOption;
        int m_fileCount;
        long long m_totalSize;
        double m_scanTime;
        std::string m_extension;

        int PerformFileScan();
        int ScanDirectory();
        int MoveDetectedMalware();
        int MoveFile(const std::string& filePath, const std::string& quarantineDir);
        int PrintScanResult();
};