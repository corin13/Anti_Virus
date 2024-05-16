#include <getopt.h>
#include <iostream>
#include <sys/ptrace.h>
#include <chrono>
#include <cstdlib>
#include <unistd.h>
#include <cstring>
#include <errno.h>
#include <filesystem>
#include <string>
#include <fstream>
#include <dirent.h>
#include "process.h"
#include <dirent.h>
#include <fstream>
#include <vector>

using namespace std;

struct option options[]={
    {"help", no_argument, 0, 'h'},
    {"info", no_argument, 0, 'i'},
    {"detect", required_argument, 0, 'd'},
    {"scan", no_argument, 0,'s'}, //인자값 필요로 한다면 no_argument -> required_argument
    {"ps", no_argument, 0, 'p'},
    {0,0,0,0}
};

void scan(){
    cout << " " << endl;
}

void error();

void help();

void info();

int logic1(){
    cout << "logic1" << endl;
    return 0;
}

int self(void){
    return 0;
}

void detect(char* argv){
    if(strcmp(argv, "logic1") == 0){
        logic1();
    } else if(strcmp(argv, "self") == 0){
        self();
    }
}
