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
#include "email_sender.h"
#include "event_monitor.h"
#include "integrity_checker.h"
#include "util.h"


int StartMonitoring() {
    std::cout << "\nPlease select the task you'd like to perform:\n\n"
        << "1. Perform a file event integrity check (Default)\n"
        << "2. Send today's log file to an email\n\n"
        << "Please enter the option: ";
    
    std::string taskTypeInput;
    getline(std::cin, taskTypeInput);
    if (taskTypeInput != "1" && taskTypeInput != "2" && !taskTypeInput.empty()) {
        return ERROR_INVALID_OPTION;
    }

    if(taskTypeInput == "1" || taskTypeInput.empty()) {
        std::cout << "\n- Monitor List -\n\n";

        std::string watchListFile = "watch_list.ini";
        
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
        std::cout << "\n### File Event Monitoring Start ! ###\n\n";
        RunEventLoop(inotifyFd, watchDescriptors);
        close(inotifyFd);
    } else if(taskTypeInput == "2") {
        if (SendEmailWithAttachment() == 0) {
            std::cout << "Email sent successfully." << std::endl;
            return SUCCESS_CODE;
        } else {
            return ERROR_CANNOT_SEND_EMAIL; 
        }
    }
    return SUCCESS_CODE;
}

// ini 파일에서 감시할 파일 목록을 읽어들이는 함수
std::vector<std::string> ReadWatchList(const std::string& filePath) {
    std::vector<std::string> watchList;
    std::ifstream file(filePath);
    std::string line;
    std::string currentSection;

    if (!file.is_open()) {
        HandleError(ERROR_CANNOT_OPEN_FILE, filePath);
    }

    while (std::getline(file, line)) {
        // 공백 라인 및 주석 라인 무시
        if (line.empty() || line[0] == '#') {
            continue;
        }

        // 섹션 확인
        if (line.front() == '[' && line.back() == ']') {
            currentSection = line.substr(1, line.size() - 2);
            continue;
        }

        // 키-값 쌍 처리
        std::istringstream lineStream(line);
        std::string key, value;
        if (std::getline(lineStream, key, '=') && std::getline(lineStream, value)) {
            key = Trim(key);
            value = Trim(value);
            if (key == "path" && !value.empty()) {
                watchList.push_back(value);
            }
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
                std::cout << "[+] Monitoring " << fullPath << "\n";
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
    std::string integrityResult = "Unchanged";

    std::cout << "[" << timeStream.str() << "]\n";
    if (event->mask & IN_CREATE) {
        eventDescription = "File created";
        SaveFileHash(fullPath);
        newHash = RetrieveStoredHash(fullPath);
    } else if (event->mask & IN_MODIFY) {
        eventDescription = "File modified";
        oldHash = RetrieveStoredHash(fullPath);
        SaveFileHash(fullPath);
        newHash = RetrieveStoredHash(fullPath);
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

    PrintEventsInfo(eventDescription, fullPath);
    VerifyFileIntegrity(fullPath, oldHash, newHash, integrityResult);
    LogEvent(timeStream, eventDescription, fullPath, oldHash, newHash, integrityResult);
    std::cout << "\n";
}

void PrintEventsInfo(std::string eventDescription, const std::string &filePath) {
    std::cout << "[+] Event type: " << eventDescription << "\n";
    std::cout << "[+] Target file: " << filePath;
}

// 무결성 검사 함수 구현
void VerifyFileIntegrity(const std::string &filePath, std::string oldHash, std::string newHash, std::string &integrityResult) {
    if (oldHash.empty() || newHash.empty() || newHash != oldHash) {
        std::cout << "\n[+] Integrity check: \033[31mDetected changes\033[0m\n";
        integrityResult = "Changed";
    } else {
        std::cout << "\n[+] Integrity check: \033[32mNo changes found\033[0m\n";
    }
}

// 파일 이벤트를 날짜별로 로그에 기록
void LogEvent(std::stringstream &timeStream, const std::string &eventDescription, const std::string &filePath, const std::string &oldHash, const std::string &newHash, const std::string &integrityResult) {
    // JSON 객체 생성
    Json::Value logEntry;
    logEntry["timestamp"] = timeStream.str();
    logEntry["event_type"] = eventDescription;
    logEntry["target_file"] = filePath;
    logEntry["old_hash"] = oldHash.empty() ? "N/A" : oldHash;
    logEntry["new_hash"] = newHash.empty() ? "N/A" : newHash;
    logEntry["integrity_result"] = integrityResult;
    logEntry["pid"] = Json::Int(getpid());

    struct stat fileStat;
    if (stat(filePath.c_str(), &fileStat) == 0) {
        logEntry["file_size"] = Json::UInt64(fileStat.st_size);
        //logEntry["user_id"] = Json::UInt(fileStat.st_uid);
        //logEntry["group_id"] = Json::UInt(fileStat.st_gid);
        //logEntry["file_permissions"] = std::to_string(fileStat.st_mode & 0777);
    } else {
        logEntry["file_size"] = "N/A";
        //logEntry["user_id"] = "N/A";
        //logEntry["group_id"] = "N/A";
        //logEntry["file_permissions"] = "N/A";
    }

    // JSON 객체를 문자열로 변환
    Json::StreamWriterBuilder writer;
    std::string logString = Json::writeString(writer, logEntry);
    std::string logFileName = GetLogFileName();

    // 수정 및 추가: 기존 로그 파일을 읽고 JSON 배열로 변환하는 부분
    std::ifstream logFileIn(logFileName);
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
    std::ofstream logFileOut(logFileName, std::ios::out);
    if (!logFileOut.is_open()) {
        HandleError(ERROR_CANNOT_OPEN_FILE, logFileName);
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

// 로그 파일 이름 생성 함수(날짜별로)
std::string GetLogFileName() {
    auto in_time_t = GetCurrentTime();
    std::stringstream ss;
    ss << "./logs/file_event_monitor_" << std::put_time(std::localtime(&in_time_t), "%Y%m%d") << ".log";
    return ss.str();
}