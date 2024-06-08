


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

/////////2번 옵션/////////////
int ConfigureFirewall();
int AddRule(std::vector<std::string>& words);
int UpdateRule(std::vector<std::string>& words);
int DeleteRule(std::vector<std::string>& words);
int RuleList(std::vector<std::string>& words);
//private//
void PrintConfigMenual();
bool isValidIP(const std::string& ip);
bool isValidPort(const std::string& port);
void handle_exit(int signum);
//////////////////////////

int StartFirewall();



int ViewLogs();



int Firewall();