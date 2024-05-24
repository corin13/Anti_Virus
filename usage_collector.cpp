#include <cstdio>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "usage_collector.h"

// 명령어를 실행하고 그 결과를 문자열로 반환하는 함수
int CUsageCollector::RunCommand(const char* pCommand, std::string& strResult) {
    char chOutputBuffer[128];
    strResult = "";
    FILE* pPipe = nullptr;

    try {
        pPipe = popen(pCommand, "r");
        if (!pPipe) return ERROR_CANNOT_OPEN_FILE;
        
        while (fgets(chOutputBuffer, sizeof(chOutputBuffer), pPipe) != nullptr) {
            strResult += chOutputBuffer;
        }

        if (pclose(pPipe) == -1) return ERROR_CANNOT_CLOSE_FILE_SYSTEM;
    } catch (const std::exception& e) {
        if (pPipe) pclose(pPipe);    
        return ERROR_UNKNOWN;
    }
    return SUCCESS_CODE;
}

// 데이터를 파일에 저장하는 함수
int CUsageCollector::SaveDataToFile(const std::string& strData, const std::string& strFileName) {
    std::ofstream outputFile;

    try {
        outputFile.open(strFileName, std::ios::out | std::ios::app);
        if (!outputFile) return ERROR_CANNOT_OPEN_FILE;

        outputFile << strData;

        if (!outputFile.good()) return ERROR_CANNOT_WRITE_FILE;
    } catch (const std::exception& e) {
        if (outputFile.is_open()) outputFile.close();
        return ERROR_UNKNOWN;
    }

    if (outputFile.is_open()) outputFile.close();
    return SUCCESS_CODE;
}

// 시스템의 CPU 사용량을 체크하는 함수
int CUsageCollector::GetCpuUsage(std::string& strResult) {
    int nErrorCode = RunCommand("top -b -n1 | grep 'Cpu(s)' | awk '{print $2 + $4}'", strResult);
    if (nErrorCode != SUCCESS_CODE) return nErrorCode;

    if (!strResult.empty() && strResult.back() == '\n') strResult.pop_back();
    return SUCCESS_CODE;
}

// 시스템의 디스크 I/O 사용량을 체크하는 함수
int CUsageCollector::GetDiskUsage(std::string& strResult) {
    int nErrorCode = RunCommand("iostat -dx", strResult);
    if (nErrorCode != SUCCESS_CODE) return nErrorCode;

    if (!strResult.empty() && strResult.back() == '\n') strResult.pop_back();
    return SUCCESS_CODE;
}

// 시스템의 네트워크 사용량을 체크하는 함수
int CUsageCollector::GetNetworkUsage(std::string& strResult) {
    int nErrorCode = RunCommand("ifstat 1 1", strResult);
    if (nErrorCode != SUCCESS_CODE) return nErrorCode;

    if (!strResult.empty() && strResult.back() == '\n') strResult.pop_back();
    return SUCCESS_CODE;
}

// 특정 데이터를 수집하고 이를 포매팅하여 파일에 저장
int CUsageCollector::SaveUsageToFile(const std::string& strFileName) {
    std::string strCpuUsage, strDiskUsage, strNetworkUsage;

    int nErrorCode = GetCpuUsage(strCpuUsage);
    if (nErrorCode != SUCCESS_CODE) return nErrorCode;
    
    strCpuUsage = "CPU Usage: " + strCpuUsage + "%\n\n";

    nErrorCode = GetDiskUsage(strDiskUsage);
    if (nErrorCode != SUCCESS_CODE) return nErrorCode;

    strDiskUsage = "Disk Usage:\n" + strDiskUsage + "\n";

    nErrorCode = GetNetworkUsage(strNetworkUsage);
    if (nErrorCode != SUCCESS_CODE) return nErrorCode;

    strNetworkUsage = "Network Usage:\n" + strNetworkUsage + "\n";

    std::string strUsageInfo = "********************************************************************************* Usage Information *********************************************************************************\n" + strCpuUsage + strDiskUsage + strNetworkUsage;

    nErrorCode = SaveDataToFile(strUsageInfo, strFileName);
    if (nErrorCode != SUCCESS_CODE) return nErrorCode;
    return SUCCESS_CODE;
}

int CUsageCollector::CollectAndSaveUsage() {
    std::string strFileName = "usage_data.txt";

    int result = SaveUsageToFile(strFileName);
    return result;
}