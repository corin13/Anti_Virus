#include "config_firewall.h"
#include <iostream>
#include <sstream>
#include <algorithm>

FirewallConfig& FirewallConfig::Instance() {
    static FirewallConfig instance;
    return instance;
}

bool FirewallConfig::Load(const std::string& filename) {
    try {
        m_reader = INIReader(filename);
        if (m_reader.ParseError() != 0) {
            std::cerr << "Failed to load firewall rules from " << filename << "\n";
            return false;
        }

        m_iniData.clear();
        for (const auto& section : m_reader.GetSections()) {
            std::map<std::string, std::string> sectionData;
            for (const auto& key : m_reader.GetKeys(section)) {
                sectionData[key] = m_reader.Get(section, key, "");
            }
            m_iniData[section] = sectionData;
        }

        m_writer = INIWriter(filename);

        return true;
    } catch (const std::exception &e) {
        std::cerr << "Failed to load firewall rules from " << filename << ": " << e.what() << "\n";
        return false;
    }
}

bool FirewallConfig::AddRule(const std::string& direction, const std::string& ip, const std::string& port, const std::string& action) {
    std::string ruleName =generateRuleNumber();
    m_iniData[ruleName]["direction"] = direction;
    m_iniData[ruleName]["ip"] = ip;
    m_iniData[ruleName]["port"] = port;
    m_iniData[ruleName]["action"] = action;

    bool writeResult = writeIniFile();

    return writeResult;
}

bool FirewallConfig::UpdateRule(const std::string& ruleName, const std::string& option, const std::string& newValue) {
    if (m_iniData.find(ruleName) == m_iniData.end()) return false;
    m_iniData[ruleName][option] = newValue;
    return writeIniFile();
}

bool FirewallConfig::DeleteRule(const std::string& ruleNumber) {
    if (ruleNumber == "all") {
        m_iniData.clear();
    } else {
        std::string ruleName =ruleNumber;
        if (m_iniData.find(ruleName) == m_iniData.end()) return false;
        m_iniData.erase(ruleName);
    }
    return writeIniFile();
}

std::string FirewallConfig::GetRulesList() const {
    
    std::ostringstream oss;
    for (const auto& section : m_iniData) {
        oss << "[" << section.first << "]\n";
        for (const auto& key : section.second) {
            oss << key.first << "=" << key.second << "\n";
        }
        oss << "\n";
    }
    return oss.str();
}

std::map<std::string, std::string> FirewallConfig::GetSectionData(const std::string& sectionName) const {
    if (m_iniData.find(sectionName) != m_iniData.end()) {
        return m_iniData.at(sectionName);
    }
    return {};
}

const std::map<std::string, std::map<std::string, std::string>>& FirewallConfig::GetIniData() const {
    return m_iniData;
}

std::string FirewallConfig::generateRuleNumber() {
    int maxRuleNumber = 0;
    for (const auto& section : m_iniData) {
        if (section.first.rfind("rule", 0) == 0) { 
            int ruleNumber = std::stoi(section.first.substr(4));
            maxRuleNumber = std::max(maxRuleNumber, ruleNumber);
        }
    }
    return "rule" + std::to_string(maxRuleNumber + 1);
}

bool FirewallConfig::writeIniFile() {
    return m_writer.Write(m_iniData);
}
