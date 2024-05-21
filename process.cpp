#include <iostream>
#include <fstream>
#include <string>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <cstdio>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include "process.h"

// 명령어를 실행하고 그 결과를 문자열로 반환하는 함수
std::string ExecuteCommand (const char* cmd) {
    char buffer[128];
    std::string result = "";
    FILE* pipe = popen(cmd, "r");

    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (!feof(pipe)) {
        if (fgets(buffer, 128, pipe) != NULL) {
            result += buffer;
        }
    }

    pclose(pipe);
    return result;
}

// 정보를 파일에 저장하는 함수
void SaveInfoToFile (const std::string& data, const std::string& filename) {
    std::ofstream outFile(filename, std::ios::out | std::ios::app);  

    if (!outFile) {
        std::cerr << "Error opening file." << std::endl;
        return;
    }

    outFile << data;
    outFile.close();
}

// CPU 사용량을 체크하는 함수
std::string GetCpuUsage() {
    std::string usage = ExecuteCommand("top -b -n1 | grep 'Cpu(s)' | awk '{print $2 + $4}'");

    if (!usage.empty() && usage.back() == '\n') {
        usage.pop_back();
    }

    return usage;
}

// 디스크 I/O 사용량을 체크하는 함수
std::string GetDiskUsage() {
    return ExecuteCommand("iostat -dx");
}

// 네트워크 사용량을 체크하는 함수
std::string GetNetworkUsage() {
    return ExecuteCommand("ifstat 1 1");
}

// 각 정보를 파일에 저장
void SaveAllInfo (const std::string& filename) {
    std::string cpuUsage = "CPU Usage: " + GetCpuUsage() + "%\n\n";
    std::string diskUsage = "Disk Usage:\n" + GetDiskUsage() + "\n";
    std::string networkUsage = "Network Usage:\n" + GetNetworkUsage() + "\n";

    std::string usageInfo = "********************************************************************************* Usage Information *********************************************************************************\n" + cpuUsage + diskUsage + networkUsage;

    SaveInfoToFile (usageInfo, filename);

    std::cout << "Information has been saved to '" << filename << "'.\n";
}

int CollectAndSaveResourceUsage() {
    std::string filename = "resource_usage.txt";
    SaveAllInfo(filename);

    return 0;
}