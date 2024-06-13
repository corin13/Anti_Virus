#pragma once

#include <unordered_map>
#include <string>
#include <fstream>
#include <regex>
#include <iostream>
#include <jsoncpp/json/json.h>

class LogParser {
public:
    LogParser() = default;
    ~LogParser() = default;

    std::unordered_map<std::string, std::string> ParseLogFile(const std::string& logFilePath, const std::vector<std::string>& keys);
    //std::unordered_map<std::string, std::string> ParseJsonLogFile(const std::string& logFilePath);
    std::vector<std::unordered_map<std::string, std::string>> ParseJsonLogFile(const std::string& logFilePath);


};
