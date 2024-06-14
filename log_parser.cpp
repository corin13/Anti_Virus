#include "log_parser.h"
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <vector>
#include <regex>
#include <jsoncpp/json/json.h>

std::unordered_map<std::string, std::string> LogParser::ParseLogFile(const std::string& logFilePath, const std::vector<std::string>& keys) {
    std::unordered_map<std::string, std::string> logData;
    std::ifstream logFile(logFilePath);
    if (!logFile.is_open()) {
        std::cerr << "Could not open log file: " << logFilePath << std::endl;
        return logData;
    }

    std::regex ipFloodingPattern("IP Flooding detected in (.+)");
    std::regex maliciousPacketPattern("Malicious packet detected: (.+)");
    std::regex reasonPattern("- Reason: (.+)");
    std::regex largePacketPattern("Large packet detected in (.+): (\\d+) bytes");
    std::regex loggedMessagePattern("\\[.+\\] \\[info\\] Logged message");
   // std::regex timestampPattern("\\[(.+)\\] \\[info\\] Logged message");
   // std::regex destinationIpPattern("Destination IP address: (.+)");
   // std::regex sourcePortPattern("Source port: (.+)");
   // std::regex destinationPortPattern("Destination port: (.+)");
   // std::regex protocolPattern("Protocol: (.+)");

    std::string line;
    while (std::getline(logFile, line)) {
        //std::cout << "Processing line: " << line << std::endl; // 디버깅 출력

        std::smatch match;
        if (std::find(keys.begin(), keys.end(), "출발지 IP 주소") != keys.end() && std::regex_search(line, match, ipFloodingPattern)) {
            logData["출발지 IP 주소"] = match[1];
        } else if (std::find(keys.begin(), keys.end(), "악성 패킷 출발지 IP") != keys.end() && std::regex_search(line, match, maliciousPacketPattern)) {
            logData["악성 패킷 출발지 IP"] = match[1];
        } else if (std::find(keys.begin(), keys.end(), "탐지된 이상 유형") != keys.end() && std::regex_search(line, match, reasonPattern)) {
            logData["탐지된 이상 유형"] = match[1];
        }/* else if (std::find(keys.begin(), keys.end(), "대형 패킷 출발지 IP") != keys.end() && std::regex_search(line, match, largePacketPattern)) {
            logData["대형 패킷 출발지 IP"] = match[1];
            logData["패킷 크기"] = match[2];
        } else if (std::find(keys.begin(), keys.end(), "탐지 시간") != keys.end() && std::regex_search(line, match, timestampPattern)) {
            logData["탐지 시간"] = match[1];
        } else if (std::find(keys.begin(), keys.end(), "목적지 IP 주소") != keys.end() && std::regex_search(line, match, destinationIpPattern)) {
            logData["목적지 IP 주소"] = match[1];
        } else if (std::find(keys.begin(), keys.end(), "출발지 포트") != keys.end() && std::regex_search(line, match, sourcePortPattern)) {
            logData["출발지 포트"] = match[1];
        } else if (std::find(keys.begin(), keys.end(), "목적지 포트") != keys.end() && std::regex_search(line, match, destinationPortPattern)) {
            logData["목적지 포트"] = match[1];
        } else if (std::find(keys.begin(), keys.end(), "프로토콜") != keys.end() && std::regex_search(line, match, protocolPattern)) {
            logData["프로토콜"] = match[1];
        }*/
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

    while (std::getline(logFile, line)) {
        std::istringstream iss(line);
        std::string month, day, time, hostname, kernel, timestamp, action;

        iss >> month >> day >> time >> hostname >> kernel;

        std::getline(iss, timestamp, ']');
        timestamp += "]"; 
        iss >> action;

        if (date.empty()) {
            date = month + " " + day;  
        }




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

    return logData;
}