#include "config.h"
#include "util.h"
#include <iostream>
#include <regex>
#include <sys/stat.h>

// 정적지역 변수를 이용한 싱글톤 -> 자동 소멸로 메모리 누수 없음
Config& Config::Instance() {
    static Config instance;
    return instance;
}

/*// 정적 포인터 초기화
config 사용하는 곳 모두 파악 후 수정 예정
Config* Config::instance = nullptr;

Config& Config::Instance() {
    if (instance == nullptr) {
        instance = new Config();
    }
    return *instance;
}

void Config::Destroy() {
    delete instance;
    instance = nullptr;
}*/

bool Config::Load(const std::string& filename) {
    std::cout << "Config::Load called with filename: " << filename << std::endl;
    try {
        m_reader = INIReader(filename);
        if (m_reader.ParseError() != 0) {
            std::cerr << "Failed to load configuration file from " << filename << "\n";
            return false;
        }
        emailAddress = m_reader.Get("NOTIFICATION", "emailaddress", "");
        if (emailAddress.empty()) {
            std::cerr << "Email address not found in ini file\n";
            return false;
        }
        std::cout << "Email address loaded: " << emailAddress << std::endl; // 디버그 출력
        return true;

        return true;
    } catch (const std::exception& e) {
        std::cerr << "Failed to load configuration from " << filename << ": " << e.what() << "\n";
        return false;
    }
}



std::string Config::GetScanPath() const {
    return m_reader.Get("SCAN", "path", "/");
}

int Config::GetScanType() const {
    return m_reader.GetInteger("SCAN", "scantype", 1);
}

bool Config::IsEmailAlertEnabled() const {
    return m_reader.GetBoolean("NOTIFICATION", "emailalert", false);
}

std::string Config::GetEmailAddress() const {
    return m_reader.Get("NOTIFICATION", "emailaddress", "");
}

std::string Config::GetNetworkInterface() const {
    return m_reader.Get("NETWORK", "interface", "");
}

int Config::GetNetworkPort() const {
    return m_reader.GetInteger("NETWORK", "port", 0);
}

std::string Config::GetFileExtension() const {
    return m_reader.Get("SCAN", "extension", "");
}

std::string Config::GetSpecificExtension() const {
    return m_reader.Get("SCAN", "specific_extension", "txt");
}
