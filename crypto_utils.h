#pragma once

#include <vector>
#include <string>

class CCryptoUtils {
public:
    static std::vector<unsigned char> GenerateRandomKey(int length);
    static void SaveKeyToFile(const std::vector<unsigned char>& vecKey, const std::string& strFilename);
    static std::vector<unsigned char> LoadKeyFromFile(const std::string& strFilename);
    static bool FileExists(const std::string& filename);
    static std::string GenerateHash(const std::string& data);
    static bool VerifyHash(const std::string& data, const std::string& hash);
    static std::vector<unsigned char> GetOrGenerateKey(const std::string& keyFilePath, int keyLength);
    static void SaveHashToFile(const std::string& hash, const std::string& filename);
    static std::string LoadHashFromFile(const std::string& filename);
};
