#include "aes.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <vector>
#include <string>

// 암호화 함수
std::vector<unsigned char> CAES::EncryptData(const std::string &plainText, const std::vector<unsigned char> &key) {
    std::vector<unsigned char> cipherText(plainText.size() + AES_BLOCK_SIZE);
    std::vector<unsigned char> iv(AES_BLOCK_SIZE);

    RAND_bytes(iv.data(), AES_BLOCK_SIZE);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data());

    int len;
    EVP_EncryptUpdate(ctx, cipherText.data(), &len, reinterpret_cast<const unsigned char*>(plainText.c_str()), plainText.size());
    int cipherTextLen = len;

    EVP_EncryptFinal_ex(ctx, cipherText.data() + len, &len);
    cipherTextLen += len;

    EVP_CIPHER_CTX_free(ctx);

    cipherText.resize(cipherTextLen);
    cipherText.insert(cipherText.begin(), iv.begin(), iv.end());

    return cipherText;
}

// 복호화 함수
std::string CAES::DecryptData(const std::vector<unsigned char> &cipherText, const std::vector<unsigned char> &key) {
    std::vector<unsigned char> iv(cipherText.begin(), cipherText.begin() + AES_BLOCK_SIZE);
    std::vector<unsigned char> actualCipherText(cipherText.begin() + AES_BLOCK_SIZE, cipherText.end());

    std::vector<unsigned char> plainText(actualCipherText.size());

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data());

    int len;
    EVP_DecryptUpdate(ctx, plainText.data(), &len, actualCipherText.data(), actualCipherText.size());
    int plainTextLen = len;

    EVP_DecryptFinal_ex(ctx, plainText.data() + len, &len);
    plainTextLen += len;

    EVP_CIPHER_CTX_free(ctx);

    plainText.resize(plainTextLen);
    return std::string(plainText.begin(), plainText.end());
}
