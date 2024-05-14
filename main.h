#include <getopt.h>
#include <iostream>

using namespace std;
//pr test
struct option options[]={
    {"help", no_argument, 0, 'h'},
    {"info", no_argument, 0, 'i'},
    {"background",no_argument, 0, 'b'},
    {"scan", no_argument, 0,'s'}, //인자값 필요로 한다면 no_argument -> required_argument
    {0,0,0,0}
};

void info(){
    cout << "이 프로그램은 .. " <<endl;
}

void background(){
    cout << "이 프로그램은 .. " <<endl;
}

void scan(){
    cout << "이 프로그램은 .. " <<endl;
}

void help(){
    cout << "이 프로그램은 .. " <<endl;
}