#include "config.h"
#include <iostream>

Config& Config::Instance() {
    static Config instance;
    return instance;
}

bool Config::Load(const std::string& filename) {
    reader = INIReader(filename);
    if (reader.ParseError() != 0) {
        std::cerr << "Can't load " << filename << "\n";
        return false;
    }
    loaded = true;
    std::cout << "Loaded configuration file: " << filename << "\n"; 
    return true;
}

std::string Config::GetScanPath() const {
    std::string path = loaded ? reader.Get("SCAN", "path", "/") : "/";
    std::cout << "Scan path from config: " << path << "\n"; // 디버깅, 추후 변경
    return path;

}

int Config::GetScanType() const {
    int scanType = loaded ? reader.GetInteger("SCAN", "scantype", 1) : 1;
    std::cout << "Scan type from config: " << scanType << "\n"; // 디버깅, 추후 변경
    return scanType;
}

bool Config::IsEmailAlertEnabled() const {
    return loaded ? reader.GetBoolean("NOTIFICATION", "emailalert", false) : false;
}

std::string Config::GetEmailAddress() const {
    std::string email = loaded ? reader.Get("NOTIFICATION", "emailaddress", "") : "";
    std::cout << "Email address read from config: " << email << "\n"; 
    return email;
}

std::string Config::GetNetworkInterface() const {
    return loaded ? reader.Get("NETWORK", "interface", "") : "";
}

int Config::GetNetworkPort() const {
    return loaded ? reader.GetInteger("NETWORK", "port", 0) : 0;
}
std::string Config::GetFileExtension() const {
    return loaded ? reader.Get("SCAN", "extension", "all") : "all"; // 기본값 all, 변경 가능
}