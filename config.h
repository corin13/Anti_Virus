#pragma once

#include "ini.h"
#include <string>
#include <regex>

class Config {
public:
    static Config& Instance();
    bool Load(const std::string& filename);
    
    std::string GetScanPath() const;
    int GetScanType() const;
    bool IsEmailAlertEnabled() const;
    std::string GetEmailAddress() const;
    std::string GetNetworkInterface() const;
    int GetNetworkPort() const;
    std::string GetFileExtension() const;
    std::string GetSpecificExtension() const;


private:
    Config() = default;
    INIReader m_reader;
    std::string emailAddress;

};
