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
#include "log_parser.h"


CEventMonitor::CEventMonitor() : m_inotifyFd(-1), m_vecWatchList(*(new std::vector<std::string>)), m_dbManager(nullptr) {}

CEventMonitor::~CEventMonitor() {
    if (m_inotifyFd != -1) {
        close(m_inotifyFd);
    }
    if (m_dbManager) {
        delete m_dbManager;
        m_dbManager = nullptr;
    }
}

int CEventMonitor::StartMonitoring() {
    m_dbManager = new CDatabaseManager();
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

        std::string logFilePath = getLogFilePath();
        // 로그 데이터로 이메일 전송
        SendEmailWithLogData(logFilePath);
    }
    return SUCCESS_CODE;
}

void CEventMonitor::SendEmailWithLogData(const std::string& logFilePath) {
    LogParser logParser;
    auto logData = logParser.ParseJsonLogFile(logFilePath);

    auto currentTime = std::time(nullptr);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&currentTime), "%Y-%m-%d");

    std::string emailBody = "<html><head><style>"
                            "table {width: 100%; border-collapse: collapse;}"
                            "th, td {border: 1px solid black; padding: 8px; text-align: left;}"
                            "th {background-color: #f2f2f2;}"
                            "</style></head><body>"
                            "<h2>[파일 이벤트의 로그 기록]</h2>"
                            "<p>안녕하세요,</p>"
                            "<p>다음은 " + ss.str() + " 파일 이벤트의 로그 기록입니다:</p>"
                            "<table>"
                            "<tr><th>파일 경로</th><th>시간</th><th>이벤트 타입</th><th>파일 크기</th><th>해시 값 (new)</th><th>해시 값 (old)</th><th>PID</th><th>사용자</th></tr>";

    for (const auto& entry : logData) {
        emailBody += "<tr>"
                     "<td>" + entry.at("target_file") + "</td>"
                     "<td>" + entry.at("timestamp") + "</td>"
                     "<td>" + entry.at("event_type") + "</td>"
                     "<td>" + entry.at("file_size") + " bytes</td>"
                     "<td>" + entry.at("new_hash") + "</td>"
                     "<td>" + entry.at("old_hash") + "</td>"
                     "<td>" + entry.at("pid") + "</td>"
                     "<td>" + entry.at("user") + "</td>"
                     "</tr>";
    }

    emailBody += "</table>"
                 "<p>[연락처 정보]</p>"
                 "<p>시스템 관리자: 이름 (이메일, 전화번호)</p>"
                 "<p>감사합니다.</p>"
                 "<p>우당탕 쿠당탕 드림</p>"
                 "</body></html>";

    std::string subject = "파일 이벤트의 로그 기록";

    std::string recipientEmailAddress = Config::Instance().GetEmailAddress();
    if (!recipientEmailAddress.empty()) {
        EmailSender emailSender("smtps://smtp.gmail.com", 465, recipientEmailAddress);
        if (emailSender.SendEmailWithAttachment(subject, emailBody, logFilePath) == 0) {
            std::cout << "\n" << COLOR_GREEN << "Email sent successfully." << COLOR_RESET << "\n";
        } else {
            HandleError(ERROR_CANNOT_SEND_EMAIL);
        }
    } else {
        std::cerr << "Email address is not configured.\n";
    }
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
        addPathToInotify(filePath);
    }
    std::cout << "\n";
}

// 주어진 경로를 inotify에 추가하고 하위 디렉토리를 순회하며 추가하는 함수
void CEventMonitor::addPathToInotify(const std::string& path) {
    std::stack<std::string> paths;
    paths.push(path);

    while (!paths.empty()) {
        std::string currentPath = paths.top();
        paths.pop();

        struct stat pathStat;
        if (stat(currentPath.c_str(), &pathStat) != 0) {
            PrintErrorMessage(ERROR_CANNOT_OPEN_DIRECTORY, currentPath);
            continue;
        }

        if (S_ISREG(pathStat.st_mode) || S_ISDIR(pathStat.st_mode)) {
            std::string fullPath = GetAbsolutePath(currentPath);
            int wd = inotify_add_watch(m_inotifyFd, fullPath.c_str(), IN_MODIFY | IN_CREATE | IN_DELETE | IN_MOVED_TO | IN_MOVED_FROM);
            if (wd == -1) {
                PrintErrorMessage(ERROR_CANNOT_OPEN_DIRECTORY, fullPath);
            } else {
                m_mapWatchDescriptors[wd] = fullPath; // 전체 경로를 매핑에 추가
                std::cout << COLOR_GREEN << "[+] Monitoring " << fullPath << COLOR_RESET << "\n";

                if (S_ISDIR(pathStat.st_mode)) {
                    DIR *dir = opendir(fullPath.c_str());
                    if (dir != nullptr) {
                        struct dirent *entry;
                        while ((entry = readdir(dir)) != nullptr) {
                            if (entry->d_name[0] != '.') { // 숨김 파일과 디렉토리 무시
                                std::string childPath = fullPath + "/" + entry->d_name;
                                struct stat childPathStat;
                                if (stat(childPath.c_str(), &childPathStat) == 0 && S_ISDIR(childPathStat.st_mode)) {
                                    paths.push(childPath); // 디렉토리인 경우에만 스택에 추가
                                }
                            }
                        }
                        closedir(dir);
                    } else {
                        PrintErrorMessage(ERROR_CANNOT_OPEN_DIRECTORY, fullPath);
                    }
                }
            }
        }
    }
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

    // 파일 크기 가져오기
    if (stat(data.filePath.c_str(), &pathStat) == 0) {
        data.fileSize = pathStat.st_size;
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
        data.fileSize = m_dbManager->GetFileSize(data.filePath);
        m_dbManager->RemoveFileFromDatabase(data.filePath);
    } else if (event->mask & IN_DELETE) {
        data.eventType = "File deleted";
        data.oldHash = m_dbManager->GetFileHash(data.filePath);
        data.fileSize = m_dbManager->GetFileSize(data.filePath);
        m_dbManager->RemoveFileFromDatabase(data.filePath);
    } else {
        data.eventType = "Other event occurred";
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
        logEntry["file_size"] = -1;
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