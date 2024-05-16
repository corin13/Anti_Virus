#include <iostream>
#include <unistd.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <thread>
#include <string.h>
#include <cstdlib>
#include <chrono>

using namespace std;

int logic2(){
    errno = 0;
    
    if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
        cout << "No debugging please." << endl;
        cout << "Error: " << strerror(errno) << endl;
        cout << "This will exit gdb now." << endl;
        this_thread::sleep_for(chrono::seconds(2));
        exit(EXIT_FAILURE);
    }  
    return 0;
}