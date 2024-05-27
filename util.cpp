#include <iostream>
#include <fstream>
#include <sstream>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <iomanip>
#include "util.h"

// 경로 유효성 검사 함수
bool IsDirectory(const std::string& path) {
    struct stat info;
    if (stat(path.c_str(), &info) != 0) {
        return false;
    }
    return (info.st_mode & S_IFDIR) != 0;
}

void PrintError(const std::string& message) {
    std::cerr << "\n\033[31m" << message << "\033[0m\n";
}

void PrintErrorMessage(int code) {
    std::cerr << "\n\033[31mError: " << GetErrorMessage(code) << "\033[0m\n";
}

// 에러 처리를 담당하는 함수
void HandleError(int code, const std::string& context) {
    if (code != SUCCESS_CODE) {
        std::cerr << "\n\033[31m[Error] " << GetErrorMessage(code) << "\033[0m";
        if (!context.empty()) {
            std::cerr << "\n\033[31m : " << context << "\033[0m";
        }
        std::cerr << "\n";
        exit(code);
    }
}


// 특정 확장자 파일 필터 함수
bool IsExtension(const std::string& filePath, const std::string& extension) {
    if (filePath.length() >= extension.length() &&
        filePath.substr(filePath.length() - extension.length()) == extension) {
        return true;
    }
    return false;
}

// ELF 파일 필터 함수
bool IsELFFile(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (file) {
        char magic[4];
        file.read(magic, 4);
        return (magic[0] == 0x7f && magic[1] == 0x45 && magic[2] == 0x4c && magic[3] == 0x46);
    }
    return false;
}

// SHA256 해시알고리즘을 사용해서 파일의 해시값을 계산
int ComputeSHA256(const std::string& fileName, std::string& fileHash) {
    std::ifstream file(fileName, std::ifstream::binary);
    if (!file) {
        return ERROR_CANNOT_OPEN_FILE;
    }

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    char buffer[1024];
    while (file.read(buffer, sizeof(buffer))) {
        SHA256_Update(&sha256, buffer, file.gcount());
    }
    SHA256_Update(&sha256, buffer, file.gcount());
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    fileHash = ss.str();
    return SUCCESS_CODE;
}