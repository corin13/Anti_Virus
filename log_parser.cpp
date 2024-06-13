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
   // std::regex largePacketPattern("Large packet detected in (.+): (\\d+) bytes");
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
            logData["탐지된 파일"] = entry["detected_file"].asString();
            logData["파일 크기"] = std::to_string(entry["file_size"].asInt());
            logData["해시 값"] = entry["hash_value"].asString();
            logData["이동 여부"] = entry["is_moved"].asString();
            logData["이동 후 경로"] = entry["path_after_moving"].asString();
            logData["스캔 유형"] = entry["scan_type"].asString();
            logData["탐지 시간"] = entry["timestamp"].asString();
            logData["YARA 규칙"] = entry["yara_rule"].asString();
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
        std::string logDate, action;
        iss >> logDate >> action;

        if (date.empty()) {
            date = logDate;
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