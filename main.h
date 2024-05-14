#include <getopt.h>
#include <iostream>

using namespace std;

//pr test test2
struct option options[]={
    {"help", no_argument, 0, 'h'},
    {"info", no_argument, 0, 'i'},
    {"background",no_argument, 0, 'b'},
    {"scan", no_argument, 0,'s'}, //인자값 필요로 한다면 no_argument -> required_argument
    {0,0,0,0}
};

void background(){
    cout << "이 프로그램은 .. " << endl;
}

void scan(){
    cout << "이 프로그램은 .. " << endl;
}

void help(){
    cout << "이 프로그램은 .. " << endl;
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