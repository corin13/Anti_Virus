#include "config_firewall.h"
#include <iostream>
#include <sstream>
#include <algorithm>

FirewallConfig& FirewallConfig::Instance() {
    static FirewallConfig instance;
    return instance;
}

/*bool FirewallConfig::Load(const std::string& filename) {
    reader = INIReader(filename);
    if (reader.ParseError() != 0) {
        std::cerr << "Failed to load firewall rules from " << filename << "\n";
        return false;
    }
    loaded = true;

    iniData.clear();
    for (const auto& section : reader.GetSections()) {
        std::map<std::string, std::string> sectionData;
        for (const auto& key : reader.GetKeys(section)) {
            sectionData[key] = reader.Get(section, key, "");
        }
        iniData[section] = sectionData;
    }

    writer = INIWriter(filename);

    std::cout << "Loaded firewall rules from " << filename << "\n";
    return true;
}*/

bool FirewallConfig::Load(const std::string& filename) {
    reader = INIReader(filename);
    if (reader.ParseError() != 0) {
        std::cerr << "Failed to load firewall rules from " << filename << "\n";
        return false;
    }
    loaded = true;

    iniData.clear();
    for (const auto& section : reader.GetSections()) {
        std::map<std::string, std::string> sectionData;
        for (const auto& key : reader.GetKeys(section)) {
            sectionData[key] = reader.Get(section, key, "");
        }
        iniData[section] = sectionData;
    }

    writer = INIWriter(filename);

    std::cout << "Loaded firewall rules from " << filename << "\n";
    return true;
}

bool FirewallConfig::AddRule(const std::string& direction, const std::string& ip, const std::string& port, const std::string& action) {
    if (!loaded) {
        std::cout << "AddRule failed: Config not loaded\n";
        return false;
    }

    std::string ruleNumber = GenerateRuleNumber();
    iniData[ruleNumber]["direction"] = direction;
    iniData[ruleNumber]["ip"] = ip;
    iniData[ruleNumber]["port"] = port;
    iniData[ruleNumber]["action"] = action;

    std::cout << "Attempting to write INI file\n";
    bool writeResult = WriteIniFile();
    std::cout << "Write INI file result: " << writeResult << std::endl;
    return writeResult;
}


bool FirewallConfig::UpdateRule(const std::string& ruleNumber, const std::string& option, const std::string& newValue) {
    if (!loaded || iniData.find(ruleNumber) == iniData.end()) return false;
    iniData[ruleNumber][option] = newValue;
    return WriteIniFile();
}

bool FirewallConfig::DeleteRule(const std::string& ruleNumber) {
    if (!loaded || iniData.find(ruleNumber) == iniData.end()) return false;
    iniData.erase(ruleNumber);
    return WriteIniFile();
}

std::string FirewallConfig::GetRulesList() const {
    std::ostringstream oss;
    for (const auto& section : iniData) {
        oss << "[" << section.first << "]\n";
        for (const auto& key : section.second) {
            oss << key.first << "=" << key.second << "\n";
        }
        oss << "\n";
    }
    return oss.str();
}


std::map<std::string, std::string> FirewallConfig::GetSectionData(const std::string& sectionName) const {
    if (iniData.find(sectionName) != iniData.end()) {
        return iniData.at(sectionName);
    }
    return {};
}

//{section1,{key,value}, section2, {key,value}}
const std::map<std::string, std::map<std::string, std::string>>& FirewallConfig::GetIniData() const {
    return iniData;
}



std::string FirewallConfig::GenerateRuleNumber() {
    int maxRuleNumber = 0;
    for (const auto& section : iniData) {
        maxRuleNumber = std::max(maxRuleNumber, std::stoi(section.first));
    }
    return std::to_string(maxRuleNumber + 1);
}

bool FirewallConfig::WriteIniFile() {
    return writer.Write(iniData);
}
