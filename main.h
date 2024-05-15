#include <getopt.h>
#include <iostream>
#include <sys/ptrace.h>
#include <chrono>
#include <cstdlib>
#include <unistd.h>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <vector>
#include <signal.h>
#include <algorithm>
#include "antidbg.h"

using namespace std;


struct option options[]={
    {"help", no_argument, 0, 'h'},
    {"info", no_argument, 0, 'i'},
    {"detect",required_argument, 0, 'd'},
    {"scan", no_argument, 0,'s'}, //인자값 필요로 한다면 no_argument -> required_argument
    {0,0,0,0}
};

void scan(){
    cout << "이 프로그램은 .. " << endl;
}

void error(){
    cout << "Error: Invalid option" << endl;
    cout << "For usage information, type 'UdkdAgent --help'" << endl;
}

void help(){
    cout << "Usage: ./UdkdAgent [OPTIONS]" << endl;
    cout << " " << endl;
    cout << "Options: " << endl;
    cout << "  -i, --info               Print detailed information about the Agent." << endl;
    cout << "  -d, --detect             Activate the anti-debugging protection. Use this feature to safeguard sensitive code from being analyzed or tampered with by external debugging." << endl;
    cout << "  -s, --scan [path]        Scan files in the specified directory. Default is '/' if no path is provided." << endl; 
}

void info(){
    cout << "Program Information" << endl;
    cout << "=====================================================================" << endl;
    cout << "Name: UdkdAgent" << endl;
    cout << "Version: " << endl;
    cout << "Release Date: " << endl;
    cout << " " << endl;
    cout << "Description: UdkdAgent is designed to enhance system protection through anti-debugging and malware detection techniques." << endl;
    cout << " " << endl;
    cout << "Key Features include: " << endl;
    cout << "    - Malware Scanning: Eliminates potential threats before they can cause harm." << endl;
    cout << "    - Anti-Debugging: Protects sensitive code from being analyzed or manipulated by unauthorized debuggers." << endl;
    cout << " " << endl;
    cout << "This tool is essential for maintaining optimal security in vulnerable or targeted environments, providing users with peace of mind through defensive capabilities." << endl;
}

int self(void){
    if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
        cout << "No debugging please" << endl;
        cout << "This will exit gdb now." << endl;
        sleep(2);
        exit(1);
        return 1;
    }
    return 0;
}

