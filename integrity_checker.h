#pragma once

#include <string>

class CIntegrityChecker {
public:
    CIntegrityChecker(const std::string& filePath);
    std::string CalculateFileHash();
    std::string RetrieveStoredHash();
    bool IsHashFileExists();
    std::string GetHashFileName();
    void SaveFileHash();
    void RemoveFileHash();

private:
    std::string m_strFilePath;
};