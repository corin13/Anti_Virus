#pragma once

#include "ini.h"
#include <string>

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

private:
    Config() : reader(std::string("")) {} // 기본 생성자에서 std::string("")로 초기화
    INIReader reader;
    bool loaded = false;
};
