#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include "options_info.h"

// 유효하지 않은 옵션을 선택했을 때 호출되어, 오류 메시지를 출력하고 '--help' 옵션의 사용을 안내
int CUdkdAgentOptions::DisplayErrorOption() {
    std::cout << "Error: Invalid option\n"
              << "For usage information, type 'UdkdAgent --help'\n";

    return ERROR_INVALID_OPTION;
}

// '-h' 또는 '--help' 옵션을 선택했을 때 호출되어, 사용 가능한 모든 옵션과 그 설명을 출력
int CUdkdAgentOptions::DisplayHelpOption() { 
    std::cout << "Usage: ./UdkdAgent [OPTIONS]\n"
              << " \n"
              << "Options: \n"
              << "  -i, --info                  Print detailed information about the Agent.\n"
              << "  -d, --detect                Activate the anti-debugging protection. Use this feature to safeguard sensitive code from being analyzed or tampered with by external debugging.\n"
              << "  -s, --scan                  Scan files in the specified directory.\n"
              << "  -u, --usage                 Collects and stores CPU, disk, and network usage data.\n"
              << "  -l, --log                   Manages log output, ensures log security and access control, optimizes log performance, and maintains log integrity and stability.\n"
              << "  -m, --monitor               Monitor file events in the system and send the recorded log files via email.\n"
              << "  -n, --network               Generates and sends packets in real-time, captures and analyzes them to detect malicious packets, and blocks any detected malicious packets.\n"
              << "  -f, --firewall              Network Control Using Firewall Rules.\n"
              << "  -c, --config                Scan Using Custom Rules.\n\n"
              << "  * -l(log) and -n(network) option requires sudo\n";

   
    return SUCCESS_CODE;
}

// '-i' 또는 '--info' 옵션을 선택했을 때 호출되어, 프로그램에 대한 상세 정보를 출력
int CUdkdAgentOptions::DisplayInfoOption() {
    std::cout << "Program Information\n"
              << "=====================================================================\n"
              << "Name: UdkdAgent\n";

    std::ifstream osReleaseFile("/etc/os-release");
    std::string strLine;

    if (!osReleaseFile) return ERROR_CANNOT_OPEN_FILE;

    try {
        bool bFindPrettyName = false;
        while (getline(osReleaseFile, strLine)) {
            if (strLine.substr(0, 11) == "PRETTY_NAME") {
                size_t siStartPosition = strLine.find('=') + 2;
                size_t siEndPosition = strLine.length() - 1;

                if (siStartPosition > siEndPosition) return ERROR_INVALID_RANGE;

                std::string strUbuntuVersion = strLine.substr(siStartPosition, siEndPosition - siStartPosition);
                std::cout << "Ubuntu Version: " << strUbuntuVersion << std::endl;

                bFindPrettyName = true;
                break;
            }
        }
        if (!bFindPrettyName) return ERROR_FILE_NOT_FOUND;
    } catch (const std::exception& ex) {
        return ERROR_UNKNOWN;
    }

    osReleaseFile.close();

    std::cout << " \n"
              << "Description: UdkdAgent is designed to enhance system protection through anti-debugging, malware detection techniques, and inspecting processes.\n"
              << " \n"
              << "Key Features include: \n"
              << "    - Malware Scanning: Eliminates potential threats before they can cause harm.\n"
              << "    - Anti-Debugging: Protects sensitive code from being analyzed or manipulated by unauthorized debuggers.\n"
              << "    - Collect System Resource: Collects CPU usage, disk I/O, and network usage, saving the data to a file for performance analysis and optimization.\n"
              << "    - Log File Management: Manages log levels, rotation, formatting, multi-sync, and asynchronous settings to ensure log integrity.\n"
              << "    - Network Malicious Packet Analysis: captures and processes network packets, extracting and displaying the source and destination IP addresses from each IP packet transmitted over the network.\n"
              << " \n"
              << "This tool is essential for maintaining optimal security in vulnerable or targeted environments, providing users with peace of mind through defensive capabilities.\n";
              
    return SUCCESS_CODE;          
}