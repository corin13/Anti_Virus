#include "log_parser.h"
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <vector>
#include <regex>
#include <jsoncpp/json/json.h>

std::unordered_map<std::string, std::vector<std::string>> LogParser::ParsePacketLogFile(const std::string& logFilePath, const std::string& date) {
    std::unordered_map<std::string, std::vector<std::string>> logData;
    std::ifstream logFile(logFilePath);
    if (!logFile.is_open()) {
        std::cerr << "Could not open log file: " << logFilePath << std::endl;
        return logData;
    }

    std::string line;
    bool capture = false;
    while (std::getline(logFile, line)) {
        // 날짜가 포함된 라인을 찾으면 capture 시작
        if (line.find("[" + date) != std::string::npos) {
            capture = true;
        }

        // capture 상태에서는 로그를 기록
        if (capture) {
            logData[date].push_back(line);
        }

        // 다음 날짜 라인이 나오면 capture 종료
        if (capture && line.find("[2024-") != std::string::npos && line.find("[" + date) == std::string::npos) {
            capture = false;
        }
    }
    logFile.close();
    return logData;
}

std::vector<std::unordered_map<std::string, std::string>> LogParser::ParseJsonLogFile(const std::string& logFilePath) {
    std::vector<std::unordered_map<std::string, std::string>> logEntries;
    std::ifstream logFile(logFilePath, std::ifstream::binary);
    if (!logFile.is_open()) {
        std::cerr << "Could not open log file: " << logFilePath << std::endl;
        return logEntries;
    }

    Json::Value root;
    Json::CharReaderBuilder builder;
    std::string errs;

    if (!Json::parseFromStream(builder, logFile, &root, &errs)) {
        std::cerr << "Failed to parse JSON: " << errs << std::endl;
        return logEntries;
    }

    if (root.isArray()) {
        for (const auto& entry : root) {
            std::unordered_map<std::string, std::string> logData;
            logData["event_type"] = entry["event_type"].asString();
            logData["file_size"] = std::to_string(entry["file_size"].asInt());
            logData["new_hash"] = entry["new_hash"].asString();
            logData["old_hash"] = entry["old_hash"].asString();
            logData["pid"] = std::to_string(entry["pid"].asInt());
            logData["target_file"] = entry["target_file"].asString();
            logData["timestamp"] = entry["timestamp"].asString();
            logData["user"] = entry["user"].asString();
            logEntries.push_back(logData);
        }
    }

    logFile.close();
    return logEntries;
}

std::unordered_map<std::string, std::string> LogParser::ParseFirewallLog(const std::string& logFilePath) {
    std::unordered_map<std::string, std::string> logData;
    std::ifstream logFile(logFilePath);
    if (!logFile.is_open()) {
        std::cerr << "Could not open log file: " << logFilePath << std::endl;
        return logData;
    }

    std::string line;
    int totalEvents = 0;
    int allowedTraffic = 0;
    int blockedTraffic = 0;
    std::string date;
    std::stringstream logEntries;

    while (std::getline(logFile, line)) {
        std::istringstream iss(line);
        std::string month, day, time, hostname, kernel, timestamp, action;
        std::string restOfLine;

        iss >> month >> day >> time >> hostname >> kernel;

        std::getline(iss, timestamp, ']');
        timestamp += "]";
        iss >> action;

        std::getline(iss, restOfLine);

        if (date.empty()) {
            date = month + " " + day;
        }

        logEntries << "<tr>"
                   << "<td>" << time << "</td>"
                   << "<td>" << hostname << "</td>"
                   << "<td>" << action << "</td>"
                   << "<td>" << restOfLine << "</td>"
                   << "</tr>";

        totalEvents++;
        if (action == "ALLOW") {
            allowedTraffic++;
        } else if (action == "BLOCK") {
            blockedTraffic++;
        }
    }

    logFile.close();

    logData["날짜"] = date;
    logData["총 이벤트 수"] = std::to_string(totalEvents);
    logData["허용된 트래픽"] = std::to_string(allowedTraffic);
    logData["차단된 트래픽"] = std::to_string(blockedTraffic);
    logData["entries"] = logEntries.str();

    return logData;
}