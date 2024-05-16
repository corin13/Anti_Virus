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
#include "print.h"

using namespace std;

struct option options[]={
    {"help", no_argument, 0, 'h'},
    {"info", no_argument, 0, 'i'},
    {"detect", no_argument, 0, 'd'},
    {"scan", no_argument, 0,'s'}, //인자값 필요로 한다면 no_argument -> required_argument
    {"ps", no_argument, 0, 'p'},
    {0,0,0,0}
};

void scan(){
    cout << " " << endl;
}

void detect(){
    cout << " " << endl;
}