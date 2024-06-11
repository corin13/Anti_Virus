#pragma once

#include <string>
#include <vector>
#include "ini.h"

class CSecureConfig {
public:
    CSecureConfig(const std::string& iniFilename, const std::string& privateKeyPath);
    std::string getDecryptedPassword(const std::string& section, const std::string& name) const;

private:
    INIReader m_iniReader;
    std::string m_privateKeyPath;

    std::vector<unsigned char> base64Decode(const std::string& encoded) const;
    std::string decryptRSA(const std::vector<unsigned char>& encryptedData) const;
};

