#include <chrono>
#include <ctime>
#include <iostream>
#include <dirent.h>
#include <fstream>
#include <iomanip>
#include <jsoncpp/json/json.h>
#include <vector>
#include <string>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>
#include "event_monitor.h"
#include "integrity_checker.h"
#include "util.h"


int StartMonitoring() {
    std::cout << "\n### File Event Monitoring Start ! ###\n\n";

    std::string watchListFile = "watch_list.txt";
    
    // 감시할 파일 목록 읽기
    std::vector<std::string> watchList = ReadWatchList(watchListFile);
    
    // 초기화 작업 수행: 해시 값 저장
    InitializeWatchList(watchList);
    
    // inotify 인스턴스 생성
    int inotifyFd = CreateInotifyInstance();
    
    // 감시 대상 추가
    std::unordered_map<int, std::string> watchDescriptors;
    AddWatchListToInotify(inotifyFd, watchList, watchDescriptors);

    // 이벤트 대기 루프 시작
    RunEventLoop(inotifyFd, watchDescriptors);

    close(inotifyFd);
    return SUCCESS_CODE;
}

// 감시할 파일 목록을 읽어들이는 함수
std::vector<std::string> ReadWatchList(const std::string& filePath) {
    std::vector<std::string> watchList;
    std::ifstream file(filePath);
    std::string line;

    if (!file.is_open()) {
        HandleError(ERROR_CANNOT_OPEN_FILE, filePath);
    }

    while (std::getline(file, line)) {
        if (!line.empty() && line[0] != '#') {
            watchList.push_back(line);
        }
    }
    file.close();

    return watchList;
}

void InitializeWatchList(const std::vector<std::string>& watchList) {
    for (const auto& path : watchList) {
        struct stat pathStat;
        stat(path.c_str(), &pathStat);
        if (S_ISDIR(pathStat.st_mode)) {
            DIR* dir = opendir(path.c_str());
            if (dir) {
                struct dirent* entry;
                while ((entry = readdir(dir)) != nullptr) {
                    if (entry->d_type == DT_REG) {
                        std::string filePath = path + "/" + entry->d_name;
                        SaveFileHash(filePath);
                    }
                }
                closedir(dir);
            }
        } else if (S_ISREG(pathStat.st_mode)) {
            SaveFileHash(path);
        }
    }
}

// inotify 인스턴스 생성 함수
int CreateInotifyInstance() {
    int inotifyFd = inotify_init();
    if (inotifyFd == -1) {
        HandleError(ERROR_INVALID_FUNCTION);
    }
    return inotifyFd;
}

// 파일 목록을 기반으로 inotify에 감시 대상 추가 함수
void AddWatchListToInotify(int inotifyFd, const std::vector<std::string>& watchList, std::unordered_map<int, std::string>& watchDescriptors) {
    for (const auto& filePath : watchList) {
        struct stat pathStat;
        if (stat(filePath.c_str(), &pathStat) != 0) {
            HandleError(ERROR_CANNOT_OPEN_DIRECTORY, filePath);
            continue;
        }
        char buffer[PATH_MAX];
        if (realpath(filePath.c_str(), buffer) == nullptr) {
            HandleError(ERROR_CANNOT_OPEN_DIRECTORY, filePath);
            continue;
        }

        if (S_ISREG(pathStat.st_mode) || S_ISDIR(pathStat.st_mode)) {
            std::string fullPath = std::string(buffer);
            int wd = inotify_add_watch(inotifyFd, fullPath.c_str(), IN_MODIFY | IN_CREATE | IN_DELETE | IN_MOVED_TO | IN_MOVED_FROM);
            if (wd == -1) {
                HandleError(ERROR_CANNOT_OPEN_DIRECTORY, fullPath);
            } else {
                watchDescriptors[wd] = fullPath; // 전체 경로를 매핑에 추가
                std::cout << "[+] Watching " << fullPath << "\n";
            }
        }
    }
    std::cout << "\n";
}

// 이벤트 대기 루프 구현
void RunEventLoop(int inotifyFd, std::unordered_map<int, std::string>& watchDescriptors) {
    const size_t eventSize = sizeof(struct inotify_event);
    const size_t bufferSize = 1024 * (eventSize + 16);
    char buffer[bufferSize];

    while (true) {
        int length = read(inotifyFd, buffer, bufferSize);
        if (length < 0) {
            perror("Read error: ");
        }

        int i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            ProcessEvent(event, watchDescriptors); // 이벤트 처리 함수 호출
            i += eventSize + event->len;
        }
    }
}


// 이벤트 처리 함수 구현
void ProcessEvent(struct inotify_event *event, std::unordered_map<int, std::string>& watchDescriptors) {
    auto it = watchDescriptors.find(event->wd);
    if (it == watchDescriptors.end()) {
        PrintError("Unknown watch descriptor: " + event->wd);
        return;
    }

    std::string fullPath = it->second;
    struct stat pathStat;
    if (stat(fullPath.c_str(), &pathStat) == 0 && S_ISDIR(pathStat.st_mode)) {
        if (event->len > 0) {
            fullPath += "/" + std::string(event->name);
        }
    }

    // 현재 시간 얻기
    auto in_time_t = GetCurrentTime();
    auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>( std::chrono::system_clock::now().time_since_epoch()) % 1000;

    std::stringstream timeStream;
    timeStream << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %H:%M:%S");
    timeStream << '.' << std::setfill('0') << std::setw(3) << milliseconds.count();

    std::string eventDescription;
    std::string newHash;
    std::string oldHash;

    std::cout << "\n[" << timeStream.str() << "] ";
    if (event->mask & IN_CREATE) {
        eventDescription = "File created";
        SaveFileHash(fullPath);
        newHash = RetrieveStoredHash(fullPath);
    } else if (event->mask & IN_MODIFY) {
        eventDescription = "File modified";
        oldHash = RetrieveStoredHash(fullPath);
        VerifyFileIntegrity(fullPath);
        newHash = CalculateFileHash(fullPath);
    } else if (event->mask & IN_MOVED_TO) {
        eventDescription = "File moved to";
        SaveFileHash(fullPath);
        newHash = CalculateFileHash(fullPath);
        // 파일 이동 경로도 명시
    } else if (event->mask & IN_MOVED_FROM) {
        eventDescription = "File moved from";
        oldHash = RetrieveStoredHash(fullPath);
        RemoveFileHash(fullPath);
    } else if (event->mask & IN_DELETE) {
        eventDescription = "File deleted";
        oldHash = RetrieveStoredHash(fullPath);
        RemoveFileHash(fullPath);
    } else {
        eventDescription = "Other event occurred";
    }
    LogEvent(timeStream, eventDescription, fullPath, newHash, oldHash);
    PrintEventsInfo(eventDescription, fullPath);
}

void PrintEventsInfo(std::string eventDescription, const std::string &filePath) {
    std::cout << eventDescription << "\n";
    std::cout << "Monitor target: " << filePath << "\n";
}

// 무결성 검사 함수 구현
void VerifyFileIntegrity(const std::string &filePath) {
    std::string currentHash = CalculateFileHash(filePath);
    std::string storedHash = RetrieveStoredHash(filePath);

    if (currentHash != storedHash) {
        PrintError("Integrity check failed for target: " + filePath);
        // 추가적인 알림이나 로그 기록을 수행
    } else {
        std::cout << "\n\033[32mIntegrity check passed for target: " << filePath << "\033[0m\n";
    }
}

// 파일 이벤트를 날짜별로 로그에 기록
void LogEvent(std::stringstream &timeStream, const std::string &eventDescription, const std::string &filePath, const std::string &oldHash, const std::string &newHash) {
    // JSON 객체 생성
    Json::Value logEntry;
    logEntry["timestamp"] = timeStream.str();
    logEntry["event"] = eventDescription;
    logEntry["target_file"] = filePath;
    logEntry["old_hash"] = oldHash.empty() ? "N/A" : oldHash;
    logEntry["new_hash"] = newHash.empty() ? "N/A" : newHash;
    logEntry["pid"] = Json::Int(getpid());

    // JSON 객체를 문자열로 변환
    Json::StreamWriterBuilder writer;
    std::string logString = Json::writeString(writer, logEntry);

    // 로그 파일에 기록
    std::string logFileName = GetLogFileName();
    std::ofstream logFile(logFileName, std::ios::out | std::ios_base::app);
    if (!logFile.is_open()) {
        HandleError(ERROR_CANNOT_OPEN_FILE, logFileName);
    }
    logFile << logString << "\n";
    logFile.close();
}

// 로그 파일 이름 생성 함수(날짜별로)
std::string GetLogFileName() {
    auto in_time_t = GetCurrentTime();
    std::stringstream ss;
    ss << "./logs/file_event_monitor_" << std::put_time(std::localtime(&in_time_t), "%Y%m%d") << ".log";
    return ss.str();
}