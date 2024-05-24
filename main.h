#pragma once

#include <getopt.h>
#include <iostream>
#include "usage_collector.h"
#include "options_info.h"
#include "antidbg.h"
#include "scan.h"
#include "logfile_manager.h"

using namespace std;

struct option options[]={
    {"help", no_argument, 0, 'h'},
    {"info", no_argument, 0, 'i'},
    {"detect", no_argument, 0, 'd'},
    {"scan", no_argument, 0,'s'}, //인자값 필요로 한다면 no_argument -> required_argument
    {"usage", no_argument, 0, 'u'},
    {"log", no_argument, 0, 'l'},
    {0,0,0,0}
};

void CheckOpt(int argc, char** argv);



