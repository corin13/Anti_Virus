#include <fstream>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "secure_config.h"

// 생성자: INI 파일과 비밀키 경로로 클래스를 초기화
CSecureConfig::CSecureConfig(const std::string& iniFilename, const std::string& privateKeyPath)
    : m_iniReader(iniFilename), m_privateKeyPath(privateKeyPath) {
    if (m_iniReader.ParseError() != 0) {
        throw std::runtime_error("Can't load '" + iniFilename + "'");
    }
}

// Base64로 인코딩된 문자열을 디코딩하여 바이너리 벡터로 변환
std::vector<unsigned char> CSecureConfig::base64Decode(const std::string& encoded) const {
    BIO* bio = BIO_new_mem_buf(encoded.c_str(), -1);
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    std::vector<unsigned char> decoded(encoded.length());
    int decodedLength = BIO_read(bio, decoded.data(), encoded.length());
    decoded.resize(decodedLength);

    BIO_free_all(bio);
    return decoded;
}

// RSA 비밀키를 사용하여 암호화된 데이터를 복호화
std::string CSecureConfig::decryptRSA(const std::vector<unsigned char>& encryptedData) const {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    FILE* privateKeyFile = fopen(m_privateKeyPath.c_str(), "rb");
    if (!privateKeyFile) {
        //throw std::runtime_error("Unable to open private key file");
        throw std::runtime_error("이게 열릴까"+m_privateKeyPath);

    }

    RSA* rsaPrivateKey = PEM_read_RSAPrivateKey(privateKeyFile, NULL, NULL, NULL);
    fclose(privateKeyFile);

    if (!rsaPrivateKey) {
        throw std::runtime_error("Unable to read private key");
    }

    std::vector<unsigned char> decryptedData(RSA_size(rsaPrivateKey));
    int decryptedLength = RSA_private_decrypt(encryptedData.size(), encryptedData.data(), decryptedData.data(), rsaPrivateKey, RSA_PKCS1_PADDING);
    RSA_free(rsaPrivateKey);

    if (decryptedLength == -1) {
        throw std::runtime_error("Decryption failed");
    }

    return std::string(decryptedData.begin(), decryptedData.begin() + decryptedLength);
}

// INI 파일에서 암호화된 비밀번호를 읽고 복호화하여 반환
std::string CSecureConfig::getDecryptedPassword(const std::string& section, const std::string& name) const {
    std::string encryptedPasswordBase64 = m_iniReader.Get(section, name, "");
    std::vector<unsigned char> encryptedPassword = base64Decode(encryptedPasswordBase64);
    return decryptRSA(encryptedPassword);
}

// INI 파일에서 암호화된 이메일 읽고 복호화하여 반환
std::string CSecureConfig::getDecryptedEmail(const std::string& section, const std::string& name) const {
    std::string encryptedEmailBase64 = m_iniReader.Get(section, name, "");
    std::vector<unsigned char> encryptedEmail = base64Decode(encryptedEmailBase64);
    return decryptRSA(encryptedEmail);
}