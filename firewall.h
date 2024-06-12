#pragma once

#define ERROR_INVALID_INPUT (200)

#define EXIT_CONFIG (-1)

////////////////////////////////
#define COMMAND (0)
////////////////////////////////
//ADD
#define ADD_MAX_LENGTH (5)
#define ADD_MIN_LENGHT (4)
#define ADD_DIRECTION (1)
#define ADD_IP (2)
#define ADD_PORT (3)
#define ADD_ACTION (4)
////////////////////////////////
//UPDATE
#define UPDATE_LENGTH (4)
#define UPDATE_NUMBER (1)
#define UPDATE_OPTION (2)
#define UPDATE_REDIRECTION (3)
#define UPDATE_NEW_VALUE (4)
////////////////////////////////
//DELETE
#define DELETE_LENGTH (2)
#define DELETE_NUMBER (1)

enum iniFormat {
    ACTION=0,
    DIRECTION,
    IP,
    PORT
};

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

#include "error_codes.h"
#include "VariadicTable.h"
#include "config_firewall.h"
#include "ansi_color.h"

int Firewall();

int RunFirewall();
int ConfigureFirewall();
int ViewLogs();

int AddRule(std::vector<std::string>& words);
int UpdateRule(std::vector<std::string>& words);
int DeleteRule(std::vector<std::string>& words);
int RuleList();

void PrintConfigMenual();

void handle_exit(int signum);

void ExecCommand(std::string cmd);
int FirewallHelp();

std::vector<std::string> ConfigureUserInput(std::string& input);

int RunIptables();
int RunIptables(std::string direction, std::string ip, std::string port, std::string action);

int isVaildInput(std::vector<std::string>& words);
bool isValidIP(const std::string& ip);
bool isValidPort(const std::string& port);