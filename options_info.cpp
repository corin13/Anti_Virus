#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include "options_info.h"

// 유효하지 않은 옵션을 선택했을 때 호출되어, 오류 메시지를 출력하고 '--help' 옵션의 사용을 안내
void CUdkdAgentOptions::DisplayErrorOption() {
    std::cout << "Error: Invalid option\n"
              << "For usage information, type 'UdkdAgent --help'\n";
}

// '-h' 또는 '--help' 옵션을 선택했을 때 호출되어, 사용 가능한 모든 옵션과 그 설명을 출력
void CUdkdAgentOptions::DisplayHelpOption() { 
    std::cout << "Usage: ./UdkdAgent [OPTIONS]\n"
              << " \n"
              << "Options: \n"
              << "  -i, --info               Print detailed information about the Agent.\n"
              << "  -d, --detect             Activate the anti-debugging protection. Use this feature to safeguard sensitive code from being analyzed or tampered with by external debugging.\n"
              << "  -s, --scan               Scan files in the specified directory.\n"
              << "  -u, --usage              Collects and stores CPU, disk, and network usage data.\n"
              << "  -l, --log                Manages log output, ensures log security and access control, optimizes log performance, and maintains log integrity and stability.\n";
}

// '-i' 또는 '--info' 옵션을 선택했을 때 호출되어, 프로그램에 대한 상세 정보를 출력
void CUdkdAgentOptions::DisplayInfoOption() {
    std::cout << "Program Information\n"
              << "=====================================================================\n"
              << "Name: UdkdAgent\n";

    std::ifstream osReleaseFile("/etc/os-release");
    std::string strLine;

    if (!osReleaseFile) {
        std::cerr << "Failed to open /etc/os-release. Error: " << strerror(errno) << std::endl;
        return;
    }

    try {
        bool bFindPrettyName = false;

        while (getline(osReleaseFile, strLine)) {
            if (strLine.substr(0, 11) == "PRETTY_NAME") {
                size_t siStartPosition = strLine.find('=') + 2;
                size_t siEndPosition = strLine.length() - 1;

                if (siStartPosition > siEndPosition) {
                    throw std::out_of_range("Invalid range for substr extraction");
                }

                std::string strUbuntuVersion = strLine.substr(siStartPosition, siEndPosition - siStartPosition);
                std::cout << "Ubuntu Version: " << strUbuntuVersion << std::endl;

                bFindPrettyName = true;
                break;
            }
        }

        if (!bFindPrettyName) {
            std::cerr << "PRETTY_NAME not found in /etc/os-release" << std::endl;
        }
    } catch (const std::exception& fileException) {
        std::cerr << "An error occurred while parsing /etc/os-release: " << fileException.what() << std::endl;
    }

    osReleaseFile.close();

    std::cout << " \n"
              << "Description: UdkdAgent is designed to enhance system protection through anti-debugging, malware detection techniques, and inspecting processes.\n"
              << " \n"
              << "Key Features include: \n"
              << "    - Malware Scanning: Eliminates potential threats before they can cause harm.\n"
              << "    - Anti-Debugging: Protects sensitive code from being analyzed or manipulated by unauthorized debuggers.\n"
              << "    - Inspect Process: Focuses on overseeing processes that use excessive resources or act unpredictably, and terminates then as needed to maintain system stability and security.\n"
              << " \n"
              << "This tool is essential for maintaining optimal security in vulnerable or targeted environments, providing users with peace of mind through defensive capabilities.\n";
}