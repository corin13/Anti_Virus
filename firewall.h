#define ERROR_INVALID_INPUT (200)

#define EXIT_CONFIG (-1)



////////////////////////////////
#define COMMAND (0)
////////////////////////////////
//ADD
#define ADD_MAX_LENGTH (5)
#define ADD_MIN_LENGHT (4)
#define A_DIRECTION (1)
#define A_IP (2)
#define A_PORT (3)
#define A_ACTION (4)
////////////////////////////////
//UPDATE
#define UPDATE_LENGTH (4)
#define U_NUMBER (1)
#define U_OPTION (2)
#define U_REDIRECTION (3)
#define U_NEW_VALUE (4)
////////////////////////////////
//DELETE
#define DELETE_LENGTH (2)
#define D_NUMBER (1)

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
#include "ini_github.h"
#include "config_firewall.h"


/////////2번 옵션/////////////
int ConfigureFirewall();
int AddRule(std::vector<std::string>& words);
int UpdateRule(std::vector<std::string>& words);
int DeleteRule(std::vector<std::string>& words);
int RuleList();
//private//
void PrintConfigMenual();
bool isValidIP(const std::string& ip);
bool isValidPort(const std::string& port);
void handle_exit(int signum);
//////////////////////////

int StartFirewall();
int RunIptables();


std::vector<std::string> ConfigureUserInput(std::string& input);

int ViewLogs();

int Firewall();

int RunIptables(std::string direction, std::string ip, std::string port, std::string action);


int RunFirewall();
int isVaildInput(std::vector<std::string>& words);
void ExecCommand(std::string cmd);
int FirewallHelp();