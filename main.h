#include <getopt.h>
#include <iostream>
#include <thread>

using namespace std;
//pr test test2
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

int logic1(){


    return 0;
}

int logic2(){
    return 0;
}

void background(){
    while (1){
        cout << "Anti-debugging Logic Running…" << endl;

        logic1();
        logic2();
        this_thread::sleep_for(chrono::seconds(1));
        
    }
}




void scan(){
    cout << "이 프로그램은 .. " <<endl;
}

void help(){
    cout << "이 프로그램은 .. " <<endl;
}