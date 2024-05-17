
#include <getopt.h>
#include <iostream>
#include "process.h"
#include "print.h"
#include "antidbg.h"
#include "scan.h"

using namespace std;

struct option options[]={
    {"help", no_argument, 0, 'h'},
    {"info", no_argument, 0, 'i'},
    {"detect", no_argument, 0, 'd'},
    {"scan", no_argument, 0,'s'}, //인자값 필요로 한다면 no_argument -> required_argument
    {"ps", no_argument, 0, 'p'},
    {0,0,0,0}
};

void CheckOpt(int argc, char** argv);



