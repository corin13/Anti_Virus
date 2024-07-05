#pragma once

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <vector>
#include <string>

// AES 암호화 및 복호화 클래스
class CAES {
public:
    static std::vector<unsigned char> EncryptData(const std::string &plainText, const std::vector<unsigned char> &key);
    static std::string DecryptData(const std::vector<unsigned char> &cipherText, const std::vector<unsigned char> &key);

private:
    static const int AES_KEY_LENGTH = 256; // AES-256 키 길이
    //static const int AES_BLOCK_SIZE = 16;  AES 블록 크기 이미 define 됨
};

