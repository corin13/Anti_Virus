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
std::string CUsageCollector::RunCommand (const char* command) {
    char chOutputBuffer[128];
    std::string strCommandResult = "";
    FILE* pPipe = nullptr;

    try {
        pPipe = popen(command, "r");
        if (!pPipe) {
            throw std::runtime_error("popen() failed!");
        }
        
        while (fgets(chOutputBuffer, sizeof(chOutputBuffer), pPipe) != nullptr) {
            strCommandResult += chOutputBuffer;
        }

        pclose(pPipe);
    } catch (const std::exception& e) {
        if (pPipe) pclose(pPipe);
        std::cerr << "Exception caught in RunCommand: " << e.what() << std::endl;
        throw; // Re-throw the exception for further handling.
    }

    return strCommandResult;
}

// 데이터를 파일에 저장하는 함수
void CUsageCollector::SaveDataToFile (const std::string& strData, const std::string& strFileName) {
    std::ofstream outputFile;

    try {
        outputFile.open(strFileName, std::ios::out | std::ios::app);
        if (!outputFile) {
            throw std::runtime_error("Failed to open file: " + strFileName);
        }

        outputFile << strData;  

        if (!outputFile.good()) {
            throw std::runtime_error("Failed to write data to file: " + strFileName);
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception caught in SaveDataToFile: " << e.what() << std::endl;
        if (outputFile.is_open()) outputFile.close();
        throw;
    }

    if (outputFile.is_open()) {
        outputFile.close();
    }
}

// 시스템의 CPU 사용량을 체크하는 함수
std::string CUsageCollector::GetCpuUsage() {
    try {
        std::string strCpuUsage = RunCommand("top -b -n1 | grep 'Cpu(s)' | awk '{print $2 + $4}'");
        if (!strCpuUsage.empty() && strCpuUsage.back() == '\n') {
            strCpuUsage.pop_back();
        }

        return strCpuUsage;
    } catch (const std::exception& e) {
        std::cerr << "Exception caught in GetCpuUsage: " << e.what() << std::endl;
        return "Error retrieving CPU usage";
    }
}

// 시스템의 디스크 I/O 사용량을 체크하는 함수
std::string CUsageCollector::GetDiskUsage() {
    try {
        std::string strDiskUsage = RunCommand("iostat -dx");
        if (!strDiskUsage.empty() && strDiskUsage.back() == '\n') {
            strDiskUsage.pop_back();
        }
        
        return strDiskUsage;
    } catch (const std::exception& e) {
        std::cerr << "Exception caught in GetDiskUsage: " << e.what() << std::endl;
        return "Error retrieving DISK usage";
    }
}

// 시스템의 네트워크 사용량을 체크하는 함수
std::string CUsageCollector::GetNetworkUsage() {
    try {
        std::string strNetworkUsage = RunCommand("ifstat 1 1");
        if (!strNetworkUsage.empty() && strNetworkUsage.back() == '\n') {
            strNetworkUsage.pop_back();
        }
        
        return strNetworkUsage;
    } catch (const std::exception& e) {
        std::cerr << "Exception caught in GetNetworkUsage: " << e.what() << std::endl;
        return "Error retrieving NETWORK usage";
    }
}

// 특정 데이터를 수집하고 이를 포매팅하여 파일에 저장
void CUsageCollector::SaveUsageToFile (const std::string& strFileName) {
    try {
        std::string strCpuUsage = "CPU Usage: " + GetCpuUsage() + "%\n\n";
        std::string strDiskUsage = "Disk Usage:\n" + GetDiskUsage() + "\n";
        std::string strNetworkUsage = "Network Usage:\n" + GetNetworkUsage() + "\n";
        std::string strUsageInfo = "********************************************************************************* Usage Information *********************************************************************************\n" + strCpuUsage + strDiskUsage + strNetworkUsage;
        
        SaveDataToFile(strUsageInfo, strFileName);
        std::cout << "Information has been saved to '" << strFileName << "'.\n";
    } catch (const std::exception& e) {
        std::cerr << "Exception caught in SaveUsageToFile: " << e.what() << std::endl;
    }
}

int CUsageCollector::CollectAndSaveUsage() {
    std::string strFileName = "usage_data.txt";
    SaveUsageToFile(strFileName);

    return 0;
}