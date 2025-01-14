#pragma once

#include "ini.h"
#include <string>
#include <map>

class FirewallConfig {
public:
    static FirewallConfig& Instance();
    bool Load(const std::string& filename);

    bool AddRule(const std::string& direction, const std::string& ip, const std::string& port, const std::string& action);
    bool UpdateRule(const std::string& ruleNumber, const std::string& option, const std::string& newValue);
    bool DeleteRule(const std::string& ruleNumber);
    std::string GetRulesList() const;
    std::map<std::string, std::string> GetSectionData(const std::string& sectionName) const;
    const std::map<std::string, std::map<std::string, std::string>>& GetIniData() const;

private:
    FirewallConfig() = default;
    INIReader m_reader;
    INIWriter m_writer;
    std::map<std::string, std::map<std::string, std::string>> m_iniData;
    std::vector<std::string> m_sectionOrder;
    std::string generateRuleNumber();
    bool writeIniFile();
};
