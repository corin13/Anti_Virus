#include <iostream>
#include <fstream>
#include <sys/types.h>
#include <sys/stat.h>
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