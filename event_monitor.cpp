#include <chrono>
#include <ctime>
#include <iostream>
#include <dirent.h>
#include <fstream>
#include <iomanip>
#include <vector>
#include <sstream>
#include <string>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>
#include "event_monitor.h"
#include "integrity_checker.h"
#include "util.h"


int StartMonitoring() {
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
        if (stat(path.c_str(), &pathStat) == 0 && S_ISREG(pathStat.st_mode)) {
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
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    std::stringstream timeStream;
    timeStream << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %H:%M:%S");
    timeStream << '.' << std::setfill('0') << std::setw(3) << milliseconds.count();

    std::string eventDescription;

    std::cout << "\n[" << timeStream.str() << "] ";
    if (event->mask & IN_CREATE) {
        eventDescription = "File created";
        PrintEventsInfo(eventDescription, fullPath);
        SaveFileHash(fullPath);
    } else if (event->mask & IN_MODIFY) {
        eventDescription = "File modified";
        PrintEventsInfo(eventDescription, fullPath);
        // 파일 무결성 검사 수행
        VerifyFileIntegrity(fullPath);
    } else if (event->mask & IN_MOVED_TO) {
        eventDescription = "File moved to";
        PrintEventsInfo(eventDescription, fullPath);
        // 파일 이동 경로도 명시
    } else if (event->mask & IN_MOVED_FROM) {
        eventDescription = "File moved from";
        PrintEventsInfo(eventDescription, fullPath);
    } else if (event->mask & IN_DELETE) {
        eventDescription = "File deleted";
        PrintEventsInfo(eventDescription, fullPath);
        // 파일 삭제 시 처리 (필요한 경우 추가 로직 구현)
        // 해시값도 삭제
    } 

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