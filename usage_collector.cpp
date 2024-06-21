#include <cstdio>
#include <dirent.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>
#include "usage_collector.h"

// 명령어를 실행하고 그 결과를 문자열로 반환하는 함수
int CUsageCollector::RunCommand(const char* pCommand, std::string& strResult) {
    char chOutputBuffer[BUFFER_SIZE];
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
    int nErrorCode = RunCommand("mpstat -P ALL 1 1", strResult);
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

// 시스템의 네트워크 인터페이스 목록을 가져오는 함수
int CUsageCollector::GetNetworkInterfaces(std::vector<std::string>& strInterfaces) {
    std::string strResult;
    int nErrorCode = RunCommand("ls /sys/class/net", strResult);
    if (nErrorCode != SUCCESS_CODE) return nErrorCode;

    std::istringstream ss(strResult);
    std::string strLine;
    while (std::getline(ss, strLine)) {
        if (!strLine.empty()) strInterfaces.push_back(strLine);
    }
    return SUCCESS_CODE;
}

// 시스템의 네트워크 사용량을 체크하는 함수
int CUsageCollector::GetNetworkUsage(std::string& strResult) {
    std::vector<std::string> strInterfaces;
    int nErrorCode = GetNetworkInterfaces(strInterfaces);
    if (nErrorCode != SUCCESS_CODE) return nErrorCode;

    strResult = "## Network Usage:\n";
    for (const auto& iface : strInterfaces) {
        std::string strIfaceResult;
        std::string command = "sar -n DEV 1 1 | grep " + iface;
        nErrorCode = RunCommand(command.c_str(), strIfaceResult);
        if (nErrorCode == SUCCESS_CODE) {
            strResult += iface + ":\n" + strIfaceResult + "\n";
        }
    }
    return SUCCESS_CODE;
}

// 특정 데이터를 수집하고 이를 포매팅하여 파일에 저장
int CUsageCollector::SaveUsageToFile(const std::string& strFileName, bool bCpu, bool bDisk, bool bNetwork) {
    std::string strCpuUsage, strDiskUsage, strNetworkUsage, strUsageInfo;
    try {
        if (bCpu) {
            int nErrorCode = GetCpuUsage(strCpuUsage);
            if (nErrorCode != SUCCESS_CODE) return nErrorCode;
            strCpuUsage = "\n## CPU Usage:\n" + strCpuUsage + "\n";
            strUsageInfo += strCpuUsage;
        }

        if (bDisk) {
            int nErrorCode = GetDiskUsage(strDiskUsage);
            if (nErrorCode != SUCCESS_CODE) return nErrorCode;
            strDiskUsage = "\n## Disk Usage:\n" + strDiskUsage;
            strUsageInfo += strDiskUsage;
        }

        if (bNetwork) {
            int nErrorCode = GetNetworkUsage(strNetworkUsage);
            if (nErrorCode != SUCCESS_CODE) return nErrorCode;
            strUsageInfo += strNetworkUsage;
        }

        strUsageInfo = "********************************************************************************* Usage Information *********************************************************************************\n" + strCpuUsage + strDiskUsage + strNetworkUsage;

        int nErrorCode = SaveDataToFile(strUsageInfo, strFileName);
        if (nErrorCode != SUCCESS_CODE) return nErrorCode;
        return SUCCESS_CODE;
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return ERROR_UNKNOWN;
    }
}

// 사용자의 입력을 받아 수집할 데이터 유형을 선택하고 저장하는 함수
int CUsageCollector::CollectAndSaveUsage() {
    std::string filename = "usage_data.txt";
    bool bCollectCpu = false;
    bool bCollectDisk = false;
    bool bCollectNetwork = false;

    try{
        std::cout << "\n## 1. Do you want to collect CPU usage? (y/n): ";
        std::string input;
        std::getline(std::cin, input);
        if (input == "y") {
            bCollectCpu = true;
        }

        std::cout << "## 2. Do you want to collect Disk usage? (y/n): ";
        std::getline(std::cin, input);
        if (input == "y") {
            bCollectDisk = true;
        }

        std::cout << "## 3. Do you want to collect Network usage? (y/n): ";
        std::getline(std::cin, input);
        if (input == "y") {
            bCollectNetwork = true;
        }

        // 사용자가 모두 n을 선택한 경우
        if (!bCollectCpu && !bCollectDisk && !bCollectNetwork) {
            std::cerr << COLOR_GREEN << "\nNo data collection selected. Exiting." << COLOR_RESET << std::endl;
            return ERROR_UNKNOWN;
        }

        int result = SaveUsageToFile(filename, bCollectCpu, bCollectDisk, bCollectNetwork);
        if (result != SUCCESS_CODE) {
            return result;
        }

        std::cout << COLOR_GREEN << "\nOutput has been saved to " << filename << COLOR_RESET << std::endl;
        return SUCCESS_CODE;
    } catch (const std::exception& e) {
       std::cerr << "Exception: " << e.what() << std::endl;
       return ERROR_UNKNOWN;
   }
}