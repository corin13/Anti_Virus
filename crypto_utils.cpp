#include "crypto_utils.h"
#include <openssl/rand.h>
#include <fstream>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>



std::vector<unsigned char> CCryptoUtils::GenerateRandomKey(int length) {
    std::vector<unsigned char> key(length);
    RAND_bytes(key.data(), length);
    return key;
}

void CCryptoUtils::SaveKeyToFile(const std::vector<unsigned char>& key, const std::string& filename) {
    std::ofstream file(filename, std::ios::binary);
    if (file.is_open()) {
        file.write(reinterpret_cast<const char*>(key.data()), key.size());
        file.close();
    }
}

std::vector<unsigned char> CCryptoUtils::LoadKeyFromFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    std::vector<unsigned char> key((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return key;
}

bool CCryptoUtils::FileExists(const std::string& filename) {
    struct stat buffer;
    return (stat(filename.c_str(), &buffer) == 0);
}

std::string CCryptoUtils::GenerateHash(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.c_str(), data.size());
    SHA256_Final(hash, &sha256);

    std::stringstream sha;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        sha << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return sha.str();
}

bool CCryptoUtils::VerifyHash(const std::string& data, const std::string& hash) {
    return GenerateHash(data) == hash;
}

std::vector<unsigned char> CCryptoUtils::GetOrGenerateKey(const std::string& keyFilePath, int keyLength) {
    std::vector<unsigned char> key = LoadKeyFromFile(keyFilePath);
    if (key.empty()) {
        key = GenerateRandomKey(keyLength);
        SaveKeyToFile(key, keyFilePath);
    }
    return key;
}

void CCryptoUtils::SaveHashToFile(const std::string& hash, const std::string& filename) {
    std::ofstream file(filename, std::ios::binary);
    if (file.is_open()) {
        file << hash;
        file.close();
    }
}

std::string CCryptoUtils::LoadHashFromFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}