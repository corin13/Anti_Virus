#include <iostream>
#include <fstream>
#include <string>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <cstdio>
#include "process.h"

using namespace std;

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

void DisplayProcessInfo(const string& processName, const string& filename){
    string cmd = "pidof " + processName;
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
    system(resourceCmd.c_str());

    char choice;
    cout << "Do you want to kill the process? (Y/N): ";
    cin >> choice;

    if(choice == 'Y' || choice == 'y'){
        string killCmd = "pkill -f " + processName;
        system(killCmd.c_str());
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