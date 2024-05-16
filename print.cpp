#include <iostream>

using namespace std;

void error(){
    cout << "Error: Invalid option\n"
         << "For usage information, type 'UdkdAgent --help'\n";
}

void help(){
    cout << "Usage: ./UdkdAgent [OPTIONS]\n"
         << " \n"
         << "Options: \n"
         << "  -i, --info               Print detailed information about the Agent.\n"
         << "  -d, --detect             Activate the anti-debugging protection. Use this feature to safeguard sensitive code from being analyzed or tampered with by external debugging.\n"
         << "  -s, --scan [path]        Scan files in the specified directory. Default is '/' if no path is provided.\n"
         << "  -p, --ps                 Focuses on overseeing processes that use excessive resources or act unpredictably, and terminates then as needed to maintain system stability and security.\n";
}

void info(){
    cout << "Program Information\n"
         << "=====================================================================\n"
         << "Name: UdkdAgent\n"
         << "Version: \n"
         << "Release Date: \n"
         << " \n" 
         << "Description: UdkdAgent is designed to enhance system protection through anti-debugging and malware detection techniques.\n"
         << " \n"
         << "Key Features include: \n"
         << "    - Malware Scanning: Eliminates potential threats before they can cause harm.\n"
         << "    - Anti-Debugging: Protects sensitive code from being analyzed or manipulated by unauthorized debuggers.\n"
         << " \n"
         << "This tool is essential for maintaining optimal security in vulnerable or targeted environments, providing users with peace of mind through defensive capabilities.\n";
}