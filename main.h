#pragma once

#include <getopt.h>
#include <iostream>
#include "antidbg.h"
#include "config.h"
#include "event_monitor.h"
#include "file_scanner.h"
#include "firewall.h"
#include "logfile_manager.h"
#include "options_info.h"
#include "packet_generator.h"
#include "packet_handler.h"
#include "usage_collector.h"
#include "user_program.h"
#include "email_sender.h"

#define CONFIGPATH "./config.ini"

// 인자값 필요로 한다면 no_argument -> required_argument
struct option options[] = {
    {"help", no_argument, 0, 'h'},
    {"info", no_argument, 0, 'i'},
    {"detect", no_argument, 0, 'd'},
    {"scan", no_argument, 0,'s'}, 
    {"usage", no_argument, 0, 'u'},
    {"log", no_argument, 0, 'l'},
    {"monitor", no_argument, 0, 'm'},
    {"network", no_argument, 0, 'n'},
    {"config", required_argument, 0, 'c'},
    {"firewall", no_argument, 0, 'f'},
    {"email", no_argument, 0, 'e'},
    {0,0,0,0}
};

void CheckOption(int &argc, char** &argv);
void LoadConfig(const std::string& configPath);
