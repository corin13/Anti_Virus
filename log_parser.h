#pragma once

#include <unordered_map>
#include <string>
#include <fstream>
#include <regex>
#include <iostream>
#include <jsoncpp/json/json.h>

class LogParser {
public:
    LogParser() {}
    ~LogParser() {}

    std::unordered_map<std::string, std::vector<std::string>> ParsePacketLogFile(const std::string& logFilePath, const std::string& date);
    std::vector<std::unordered_map<std::string, std::string>> ParseJsonLogFile(const std::string& logFilePath);
    std::unordered_map<std::string, std::string> ParseFirewallLog(const std::string& logFilePath);



};
