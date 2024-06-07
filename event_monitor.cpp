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
#include "ansi_color.h"
#include "email_sender.h"
#include "event_monitor.h"
#include "integrity_checker.h"
#include "util.h"

CEventMonitor::CEventMonitor() : m_inotifyFd(-1), m_watchList(*(new std::vector<std::string>)) {}

int CEventMonitor::StartMonitoring() {
    std::cout << "\nPlease select the task you'd like to perform:\n\n"
        << "1. Perform a file event integrity check (Default)\n"
        << "2. Send today's log file to an email\n\n"
        << "Please enter the option: ";
    
    std::string taskTypeInput;
    getline(std::cin, taskTypeInput);
    if (taskTypeInput != "1" && taskTypeInput != "2" && !taskTypeInput.empty()) {
        HandleError(ERROR_INVALID_OPTION);
    }

    if(taskTypeInput == "1" || taskTypeInput.empty()) {
        std::cout << "\n- Monitor List -\n\n";

        std::string watchListFile = "watch_list.ini";
        
        // 감시할 파일 목록 읽기
        m_watchList = readWatchList(watchListFile);
        
        // 초기화 작업 수행: 해시 값 저장
        initializeWatchList();
        
        // inotify 인스턴스 생성
        m_inotifyFd = createInotifyInstance();
        
        // 감시 대상 추가
        addWatchListToInotify();

        // 이벤트 대기 루프 시작
        std::cout << "\n### File Event Monitoring Start ! ###\n\n";
        runEventLoop();
        close(m_inotifyFd);

    } else if(taskTypeInput == "2") {
        EmailSender emailSender("smtps://smtp.gmail.com", 465, "udangtang02@gmail.com");
        if (emailSender.SendEmailWithAttachment() == 0) {
            std::cout << "\n" << COLOR_GREEN << "Email sent successfully." << COLOR_RESET << "\n";
        } else {
            HandleError(ERROR_CANNOT_SEND_EMAIL);
        }
    }
    return SUCCESS_CODE;
}

// ini 파일에서 감시할 파일 목록을 읽어들이는 함수
std::vector<std::string> CEventMonitor::readWatchList(const std::string& watchListfilePath) {
    std::ifstream file(watchListfilePath);
    std::string line;
    std::string currentSection;

    if (!file.is_open()) {
        HandleError(ERROR_CANNOT_OPEN_FILE, watchListfilePath);
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
                m_watchList.push_back(value);
            }
        }
    }
    file.close();
    return m_watchList;
}

void CEventMonitor::initializeWatchList() {
    for (const auto& path : m_watchList) {
        struct stat pathStat;
        stat(path.c_str(), &pathStat);
        if (S_ISDIR(pathStat.st_mode)) {
            DIR* dir = opendir(path.c_str());
            if (dir) {
                struct dirent* entry;
                while ((entry = readdir(dir)) != nullptr) {
                    if (entry->d_type == DT_REG) {
                        std::string filePath = path + "/" + entry->d_name;
                        CIntegrityChecker checker(filePath);
                        checker.SaveFileHash();
                    }
                }
                closedir(dir);
            }
        } else if (S_ISREG(pathStat.st_mode)) {
            CIntegrityChecker checker(path);
            checker.SaveFileHash();
        }
    }
}

// inotify 인스턴스 생성 함수
int CEventMonitor::createInotifyInstance() {
    int inotifyFd = inotify_init();
    if (inotifyFd == -1) {
        HandleError(ERROR_INVALID_FUNCTION);
    }
    return inotifyFd;
}

// 파일 목록을 기반으로 inotify에 감시 대상 추가 함수
void CEventMonitor::addWatchListToInotify() {
    for (const auto& filePath : m_watchList) {
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
            int wd = inotify_add_watch(m_inotifyFd, fullPath.c_str(), IN_MODIFY | IN_CREATE | IN_DELETE | IN_MOVED_TO | IN_MOVED_FROM);
            if (wd == -1) {
                HandleError(ERROR_CANNOT_OPEN_DIRECTORY, fullPath);
            } else {
                m_watchDescriptors[wd] = fullPath; // 전체 경로를 매핑에 추가
                std::cout << "[+] Monitoring " << fullPath << "\n";
            }
        }
    }
    std::cout << "\n";
}

// 이벤트 대기 루프 구현
void CEventMonitor::runEventLoop() {
    const size_t eventSize = sizeof(struct inotify_event);
    const size_t bufferSize = 1024 * (eventSize + 16);
    char buffer[bufferSize];

    while (true) {
        int length = read(m_inotifyFd, buffer, bufferSize);
        if (length < 0) {
            perror("Read error: ");
        }

        int i = 0; // 왜 필요한지??? 영원히 0인거 아닌가????? -> 생각해보기 공부!!!
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            processEvent(event); // 이벤트 처리 함수 호출
            i += eventSize + event->len;
        }
    }
}


// 이벤트 처리 함수 구현
void CEventMonitor::processEvent(struct inotify_event *event) {
    auto it = m_watchDescriptors.find(event->wd);
    if (it == m_watchDescriptors.end()) {
        PrintError("Unknown watch descriptor: " + std::to_string(event->wd));
        return;
    }

    MonitorData data = {
        .eventDescription = "",
        .filePath = it->second,
        .integrityResult = "Unchanged",
        .newHash = "",
        .oldHash = "",
        .timestamp = GetCurrentTimeWithMilliseconds()
    };

    struct stat pathStat;
    if (stat(data.filePath.c_str(), &pathStat) == 0 && S_ISDIR(pathStat.st_mode)) {
        if (event->len > 0) {
            data.filePath += "/" + std::string(event->name);
        }
    }

    CIntegrityChecker checker(data.filePath);
    std::cout << "[" << data.timestamp << "]\n";

    if (event->mask & IN_CREATE) {
        data.eventDescription = "File created";
        checker.SaveFileHash();
        data.newHash = checker.RetrieveStoredHash();
    } else if (event->mask & IN_MODIFY) {
        data.eventDescription = "File modified";
        data.oldHash = checker.RetrieveStoredHash();
        checker.SaveFileHash();
        data.newHash = checker.RetrieveStoredHash();
    } else if (event->mask & IN_MOVED_TO) {
        data.eventDescription = "File moved to";
        checker.SaveFileHash();
        data.newHash = checker.RetrieveStoredHash();
        // 파일 이동 경로도 명시
    } else if (event->mask & IN_MOVED_FROM) {
        data.eventDescription = "File moved from";
        data.oldHash = checker.RetrieveStoredHash();
        checker.RemoveFileHash();
    } else if (event->mask & IN_DELETE) {
        data.eventDescription = "File deleted";
        data.oldHash = checker.RetrieveStoredHash();
        checker.RemoveFileHash();
    } else {
        data.eventDescription = "Other event occurred";
    }

    printEventsInfo(data);
    verifyFileIntegrity(data);
    logEvent(data);
    std::cout << "\n";
}

void CEventMonitor::printEventsInfo(MonitorData& data) {
    std::cout << "[+] Event type: " << COLOR_YELLOW << data.eventDescription << COLOR_RESET << "\n";
    std::cout << "[+] Target file: " << data.filePath;
}

// 무결성 검사 함수 구현
void CEventMonitor::verifyFileIntegrity(MonitorData& data) {
    if (data.oldHash.empty() || data.newHash.empty() || data.newHash != data.oldHash) {
        std::cout << "\n[+] Integrity check: " << COLOR_RED << "Detected changes" << COLOR_RESET << "\n";
        data.integrityResult = "Changed";
    } else {
        std::cout << "\n[+] Integrity check: " << COLOR_GREEN << "No changes found" << COLOR_RESET << "\n";
    }
}

// 파일 이벤트를 날짜별로 로그에 기록
void CEventMonitor::logEvent(MonitorData& data) {
    // JSON 객체 생성
    Json::Value logEntry;
    logEntry["timestamp"] = data.timestamp;
    logEntry["event_type"] = data.eventDescription;
    logEntry["target_file"] = data.filePath;
    logEntry["old_hash"] = data.oldHash.empty() ? "N/A" : data.oldHash;
    logEntry["new_hash"] = data.newHash.empty() ? "N/A" : data.newHash;
    logEntry["integrity_result"] = data.integrityResult;
    logEntry["pid"] = Json::Int(getpid());

    struct stat fileStat;
    if (stat(data.filePath.c_str(), &fileStat) == 0) {
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

    SaveLogInJson(logEntry, getLogFilePath());
}

// 로그 파일 이름 생성 함수(날짜별로)
std::string CEventMonitor::getLogFilePath() {
    auto currentTime = GetCurrentTime();
    std::stringstream ss;
    ss << "./logs/file_event_monitor_" << std::put_time(std::localtime(&currentTime), "%y%m%d") << ".log";
    return ss.str();
}