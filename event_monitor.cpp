#include <chrono>
#include <ctime>
#include <iostream>
#include <dirent.h>
#include <fstream>
#include <iomanip>
#include <jsoncpp/json/json.h>
#include <pwd.h>
#include <vector>
#include <string>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>
#include "ansi_color.h"
#include "email_sender.h"
#include "event_monitor.h"
#include "ini.h"
#include "util.h"
#include "config.h"

CEventMonitor::CEventMonitor() : m_inotifyFd(-1), m_vecWatchList(*(new std::vector<std::string>)), m_dbManager(new CDatabaseManager()) {}

CEventMonitor::~CEventMonitor() {
    if (m_inotifyFd != -1) {
        close(m_inotifyFd);
    }
    delete m_dbManager;
}

int CEventMonitor::StartMonitoring() {
    std::cout << "\nPlease select the task you'd like to perform:\n\n"
        << "1. Perform a file event monitoring (Default)\n"
        << "2. Send today's log file to an email\n\n"
        << "Please enter the option: ";
    
    std::string taskTypeInput;
    int taskTypeOption = PERFORM_MONITORING;
    while (true) {
        getline(std::cin, taskTypeInput);
        if(taskTypeInput == "1" || taskTypeInput == "2") {
            taskTypeOption = std::stoi(taskTypeInput);
            break;
        } else if(taskTypeInput.empty()) {
            break;
        }
        PrintErrorMessage(ERROR_INVALID_OPTION);
        std::cout << "Please enter the correct option again: "; 
    }

    if(taskTypeOption == PERFORM_MONITORING) {
        std::cout << "\n- Monitor List -\n\n";
        
        // 감시할 파일 목록 읽기
        readWatchList();

        // inotify 인스턴스 생성
        createInotifyInstance();
        
        // 감시 대상 추가
        addWatchListToInotify();

        // 이벤트 대기 루프 시작
        std::cout << "\n### File Event Monitoring Start ! ###\n\n";
        runEventLoop();
        close(m_inotifyFd);

    } else if (taskTypeOption == SEND_EMAIL) {
        std::string recipientEmailAddress = Config::Instance().GetEmailAddress();
        std::cout << "Recipient email address read from config: " << recipientEmailAddress << "\n";
        if (!recipientEmailAddress.empty()) {
            EmailSender emailSender("smtps://smtp.gmail.com", 465, recipientEmailAddress);
            if (emailSender.SendEmailWithAttachment() == 0) {
                std::cout << "\n" << COLOR_GREEN << "Email sent successfully." << COLOR_RESET << "\n";
            } else {
                HandleError(ERROR_CANNOT_SEND_EMAIL);
            }
        } else {
            std::cerr << "Email address is not configured.\n";
        }
    }
    return SUCCESS_CODE;
}

// ini 파일에서 감시할 파일 목록을 읽어들이는 함수
void CEventMonitor::readWatchList() {
    INIReader reader(SETTING_FILE);

    if (reader.ParseError() != 0) {
        PrintErrorMessage(ERROR_INVALID_FUNCTION);
    }

    // monitor 섹션에서 모든 키를 가져옴
    std::vector<std::string> keys = reader.GetKeys("monitor");
    for (const std::string& key : keys) {
        // 키가 "path"로 시작하는지 확인
        if (key.find("path") == 0) {
            std::string path = reader.Get("monitor", key, "");
            if (!path.empty()) {
                m_vecWatchList.push_back(path);
            }
        }
    }
}

// inotify 인스턴스 생성 함수
void CEventMonitor::createInotifyInstance() {
    int inotifyFd = inotify_init();
    if (inotifyFd == -1) {
        HandleError(ERROR_INVALID_FUNCTION);
    }
    m_inotifyFd = inotifyFd;
}

// 파일 목록을 기반으로 inotify에 감시 대상 추가 함수
void CEventMonitor::addWatchListToInotify() {
    for (const auto& filePath : m_vecWatchList) {
        struct stat pathStat;
        if (stat(filePath.c_str(), &pathStat) != 0) {
            PrintErrorMessage(ERROR_CANNOT_OPEN_DIRECTORY, filePath);
            continue;
        }

        if (S_ISREG(pathStat.st_mode) || S_ISDIR(pathStat.st_mode)) {
            std::string fullPath = GetAbsolutePath(filePath);
            int wd = inotify_add_watch(m_inotifyFd, fullPath.c_str(), IN_MODIFY | IN_CREATE | IN_DELETE | IN_MOVED_TO | IN_MOVED_FROM);
            if (wd == -1) {
                PrintErrorMessage(ERROR_CANNOT_OPEN_DIRECTORY, fullPath);
            } else {
                m_mapWatchDescriptors[wd] = fullPath; // 전체 경로를 매핑에 추가
                std::cout << "[+] Monitoring " << fullPath << "\n";
            }
        }
    }
    std::cout << "\n";
}

// 이벤트 대기 루프 구현
void CEventMonitor::runEventLoop() {
    char buffer[EVENT_BUFFER_SIZE];

    while (true) {
        int length = read(m_inotifyFd, buffer, EVENT_BUFFER_SIZE);
        if (length < 0) {
            perror("Read error: ");
        }

        int i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            processEvent(event); // 이벤트 처리 함수 호출
            i += EVENT_SIZE + event->len;
        }
    }
}


// 이벤트 처리 함수 구현
void CEventMonitor::processEvent(struct inotify_event *event) {
    auto it = m_mapWatchDescriptors.find(event->wd);
    if (it == m_mapWatchDescriptors.end()) {
        PrintError("Unknown watch descriptor: " + std::to_string(event->wd));
        return;
    }

    ST_MonitorData data = {
        .eventType = "",
        .filePath = it->second,
        .newHash = "",
        .oldHash = "",
        .timestamp = GetCurrentTimeWithMilliseconds(),
        .fileSize = -1,
        .user = getpwuid(getuid())->pw_name,
        .processId = getpid()
    };

    struct stat pathStat;
    if (stat(data.filePath.c_str(), &pathStat) == 0 && S_ISDIR(pathStat.st_mode)) {
        if (event->len > 0) {
            data.filePath += "/" + std::string(event->name);
        }
    }

    std::cout << "[" << data.timestamp << "]";

    if (event->mask & IN_CREATE) {
        data.eventType = "File created";
        data.newHash = CalculateFileHash(data.filePath);
    } else if (event->mask & IN_MODIFY) {
        data.eventType = "File modified";
        data.oldHash = m_dbManager->GetFileHash(data.filePath);
        data.newHash = CalculateFileHash(data.filePath);
    } else if (event->mask & IN_MOVED_TO) {
        data.eventType = "File moved to";
        data.newHash = CalculateFileHash(data.filePath);
    } else if (event->mask & IN_MOVED_FROM) {
        data.eventType = "File moved from";
        data.oldHash = m_dbManager->GetFileHash(data.filePath);
        m_dbManager->RemoveFileFromDatabase(data.filePath);
    } else if (event->mask & IN_DELETE) {
        data.eventType = "File deleted";
        data.oldHash = m_dbManager->GetFileHash(data.filePath);
        m_dbManager->RemoveFileFromDatabase(data.filePath);
    } else {
        data.eventType = "Other event occurred";
    }

    // 파일 크기 가져오기
    if (stat(data.filePath.c_str(), &pathStat) == 0) {
        data.fileSize = pathStat.st_size;
    } 

    printEventsInfo(data);
    logEvent(data);
    m_dbManager->LogEventToDatabase(data);
    std::cout << "\n\n";
}

std::string CEventMonitor::CalculateFileHash(std::string filePath) {
    std::string fileHash;
    int result = ComputeSHA256(filePath, fileHash);
    if (result != SUCCESS_CODE) {
        PrintErrorMessage(ERROR_CANNOT_COMPUTE_HASH);
    }
    return fileHash;
}

void CEventMonitor::printEventsInfo(ST_MonitorData& data) {
    std::cout << "\n[+] Event type: " << COLOR_YELLOW << data.eventType << COLOR_RESET;
    std::cout << "\n[+] Target file: " << data.filePath;
}

// 파일 이벤트를 날짜별로 로그에 기록
void CEventMonitor::logEvent(ST_MonitorData& data) {
    // JSON 객체 생성
    Json::Value logEntry;
    logEntry["timestamp"] = data.timestamp;
    logEntry["event_type"] = data.eventType;
    logEntry["target_file"] = data.filePath;
    logEntry["old_hash"] = data.oldHash.empty() ? "N/A" : data.oldHash;
    logEntry["new_hash"] = data.newHash.empty() ? "N/A" : data.newHash;
    logEntry["pid"] = Json::Int(getpid());
    logEntry["user"] = data.user;

    if (data.fileSize != -1) {
        logEntry["file_size"] = Json::UInt64(data.fileSize);
    } else {
        logEntry["file_size"] = "N/A";
    }

    SaveLogInJson(logEntry, getLogFilePath());
}

// 로그 파일 이름 생성 함수(날짜별로)
std::string CEventMonitor::getLogFilePath() {
    auto currentTime = GetCurrentTime();
    std::stringstream ss;
    ss << LOG_SAVE_PATH << std::put_time(std::localtime(&currentTime), "%y%m%d") << ".log";
    return ss.str();
}