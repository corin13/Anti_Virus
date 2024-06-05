#pragma once

#include "antidbg.h"
#include <getopt.h>
#include <iostream>
#include "logfile_manager.h"
#include "options_info.h"
#include "file_scanner.h"
#include "usage_collector.h"
#include "event_monitor.h"

using namespace std;

// 인자값 필요로 한다면 no_argument -> required_argument
struct option options[]={
    {"help", no_argument, 0, 'h'},
    {"info", no_argument, 0, 'i'},
    {"detect", no_argument, 0, 'd'},
    {"scan", no_argument, 0,'s'}, 
    {"usage", no_argument, 0, 'u'},
    {"log", no_argument, 0, 'l'},
    {"monitor", no_argument, 0, 'm'},
    {0,0,0,0}
};

void CheckOpt(int argc, char** argv);