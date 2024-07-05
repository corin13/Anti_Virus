#pragma once


#define LOG_FILE_PATH "./logs/firewall/"
#define FIREWALL_INI_FILE "firewall_rules.ini"

#define EXIT_CONFIG (-1)

////////////////////////////////
#define COMMAND (0)
//ADD
#define ADD_MAX_LENGTH (5)
#define ADD_MIN_LENGTH (4)
#define ADD_DIRECTION (1)
#define ADD_IP (2)
#define ADD_PORT (3)
#define ADD_ACTION (4)
//UPDATE
#define UPDATE_LENGTH (5)
#define UPDATE_NUMBER (1)
#define UPDATE_OPTION (2)
#define UPDATE_REDIRECTION (3)
#define UPDATE_NEW_VALUE (4)
//DELETE
#define DELETE_LENGTH (2)
#define DELETE_NUMBER (1)
////////////////////////////////

enum eIniFormat {
    ACTION=0,
    DIRECTION,
    IP,
    PORT
};

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <iostream>
#include <unordered_map>
#include <functional>
#include <regex>
#include <unordered_set>
#include <cstdlib>
#include <unistd.h>
#include <csignal>
#include <algorithm>


#include "error_codes.h"
#include "VariadicTable.h"
#include "config_firewall.h"
#include "ansi_color.h"
#include "email_sender.h"
#include "log_parser.h"
#include "config.h"
#include "util.h"

class CFirewall {
public:
    int StartFirewall();
    int RunFirewall();
    int ConfigureFirewall();
    int ViewLogs();
    int RunIptables(const std::string& strDirection, const std::string& strIp, const std::string& strPort, const std::string& strAction);
    static void ExecCommand(const std::string& strCmd);

private:
    int AddRule(std::vector<std::string>& vecWords);
    int UpdateRule(std::vector<std::string>& vecWords);
    int DeleteRule(std::vector<std::string>& vecWords);
    int RuleList();

    void PrintConfigManual();
    static void handleExit(int nSignum);
    std::vector<std::string> ConfigureUserInput(std::string& strInput);
    std::string GetSectionName(const auto& vecIniData, int nNumber);
    bool isValidIP(const std::string& strIp);
    bool isValidPort(const std::string& strPort);
    bool isValidNumber(const std::string& strNumber);
    int isValidInput(std::vector<std::string>& vecWords);
    int PrintFirewallHelp();
    
};
