#include <chrono>
#include <iostream>
#include <fstream>
#include <jsoncpp/json/json.h>
#include <limits.h>
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

std::time_t GetCurrentTime() {
    auto now = std::chrono::system_clock::now();
    auto currentTime = std::chrono::system_clock::to_time_t(now);
    return currentTime;
}

std::string GetCurrentTimeWithMilliseconds() {
    auto currentTime = GetCurrentTime();
    auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>( std::chrono::system_clock::now().time_since_epoch()) % 1000;

    std::stringstream timeStream;
    timeStream << std::put_time(std::localtime(&currentTime), "%Y-%m-%d %H:%M:%S");
    timeStream << '.' << std::setfill('0') << std::setw(3) << milliseconds.count();
    return timeStream.str();
}

// 문자열의 앞뒤 공백 제거 함수
std::string Trim(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\r\n");
    size_t end = str.find_last_not_of(" \t\r\n");
    return (start == std::string::npos) ? "" : str.substr(start, end - start + 1);
}

std::string GetAbsolutePath(std::string path) {
    char absolutePath[PATH_MAX];
    if (realpath(path.c_str(), absolutePath) != nullptr) {
        return absolutePath;
    } else {
        return path;
    }
}

void SaveLogInJson(Json::Value logEntry, std::string logFilePath) {
    
    Json::StreamWriterBuilder writer;
    
    // 수정 및 추가: 기존 로그 파일을 읽고 JSON 배열로 변환하는 부분
    std::ifstream logFileIn(logFilePath);
    std::vector<Json::Value> logEntries;

    if (logFileIn.is_open()) {
        Json::CharReaderBuilder reader;
        Json::Value existingLog;
        std::string errs;
        if (Json::parseFromStream(reader, logFileIn, &existingLog, &errs)) {
            if (existingLog.isArray()) {
                for (const auto &entry : existingLog) {
                    logEntries.push_back(entry);
                }
            }
        }
        logFileIn.close();
    }

    logEntries.push_back(logEntry);

    // 수정 및 추가: JSON 배열 형식으로 로그 파일에 저장하는 부분
    std::ofstream logFileOut(logFilePath, std::ios::out);
    if (!logFileOut.is_open()) {
        HandleError(ERROR_CANNOT_OPEN_FILE, logFilePath);
    }
    logFileOut << "[\n";
    for (size_t i = 0; i < logEntries.size(); ++i) {
        logFileOut << Json::writeString(writer, logEntries[i]);
        if (i != logEntries.size() - 1) {
            logFileOut << ","; // 수정: 각 JSON 객체 사이에 쉼표 추가
        }
        logFileOut << "\n";
    }
    logFileOut << "]";
    logFileOut.close();
}