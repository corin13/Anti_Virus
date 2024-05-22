#include <iostream>
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