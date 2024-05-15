#include <iostream>
#include <sys/ptrace.h>
#include <getopt.h>
#include "main.h"
#include <chrono>
#include <thread>
#include <cstdlib>
#include <unistd.h>
#include <cstring>
#include <errno.h>
#include <filesystem>
#include <string>
#include <fstream>
#include <dirent.h>

using namespace std;

void CheckOpt(int argc, char** argv){
    int optionIndex= 0;
    int opt;
    const char* option="hid:sp"; //인자값 필요로 한다면 :붙이기 ex) hib:s:

    while((opt = getopt_long(argc, argv, option, options, &optionIndex)) != -1 ){
        switch(opt){
            case 'h':
                help(); 
                break;
            
            case 'i':
                info();
                break;

            case 's':
                scan();
                break;

            case 'd':
                detect(optarg);
                break;

            case 'p':
                process();
                break;

            case '?':
                error();
                break;
            
            default:
                abort();
        }
    }
    
}

int main(int argc, char **argv){
    
    if(self()){
        return 1;
    }
    
    //옵션 값 확인
    if (argc > 1) 
        CheckOpt(argc, argv);
    else
        cout << "Try 'UdkdAgent --help' for more information." << endl;
    
    return 0;
}
