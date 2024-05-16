#include <iostream>
#include <fstream>
#include <string>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <cstdio>
#include "process.h"

using namespace std;

// 명령어를 실행하고 그 결과를 문자열로 반환하는 함수
string exec(const char* cmd){
    char buffer[128];
    string result = "";
    FILE* pipe = popen(cmd, "r");
    
    if(!pipe){
        throw runtime_error("popen() failed!");
    }   
    while(!feof(pipe)){
        if(fgets(buffer, 128, pipe) != NULL){
            result += buffer;
        }
    }

    pclose(pipe);
    return result;
}

// 특정 프로세스의 정보를 화면에 표시하고 파일에 저장하는 함수
void DisplayProcessInfo(const string& processName, const string& filename){
    string cmd = "pidof " + processName;    //프로세스 ID를 찾기 위한 명령어
    string output = exec(cmd.c_str());
    
    if(output.empty()){
        cout << "No process found for '" << processName << "'." << endl;
        return;
    }
    
    ofstream outFile(filename);

    if(!outFile){
        cerr << "Error opening file." << endl;
        return;
    }

    outFile << output; 
    outFile.close();
    cout << "Process ID for '" << processName << "': " << output;

    cout << "Resource usage statistics saved to '" << filename << "'." << endl;
    string resourceCmd = "ps -eo pid,tty,stat,time,command | grep -e '";
    resourceCmd += processName;
    resourceCmd += "' | grep -v grep > ";
    resourceCmd += filename;
    system(resourceCmd.c_str());    // 시스템 명령어를 사용하여 프로세스 정보를 파일에 저장

    char choice;
    cout << "Do you want to kill the process? (Y/N): ";
    cin >> choice;

    if(choice == 'Y' || choice == 'y'){
        string killCmd = "pkill -f " + processName; // 프로세스 종료 명령어
        system(killCmd.c_str());    // 시스템 명령어를 사용하여 프로세스 종료
        cout << "Process killed." << endl;
    } else{
        cout << "Process not killed." << endl;
    }
}

int process(){
    string processName;
    string filename = "resource_stats.txt";

    cout << "Enter the name of the process: ";
    cin >> processName;

    DisplayProcessInfo(processName, filename);

    return 0;
}