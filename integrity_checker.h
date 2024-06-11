#pragma once

#include <string>

#define HASH_DIRECTORY "integrity-check-hashes"

class CIntegrityChecker {
public:
    CIntegrityChecker(const std::string& filePath);
    ~CIntegrityChecker();
    std::string CalculateFileHash();
    std::string RetrieveStoredHash();
    bool IsHashFileExists();
    std::string GetHashFileName();
    void SaveFileHash();
    void RemoveFileHash();

private:
    std::string m_strFilePath;
};