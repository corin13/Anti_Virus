#pragma once

#include <unordered_map>
#include <vector>
#include <string>
#include <sstream>
#include <sys/inotify.h>
#include "database_manager.h"
#include "log_parser.h"
#include "email_sender.h"

#define SETTING_FILE "settings.ini"
#define LOG_SAVE_PATH "logs/file_event_monitor_"

#define PERFORM_MONITORING 1
#define SEND_EMAIL 2

#define EVENT_SIZE (sizeof(struct inotify_event)) // 이벤트 구조체 크기
#define EVENT_BUFFER_SIZE (1024 * (EVENT_SIZE + 16)) // 한 번에 읽을 수 있는 최대 바이트 수

struct ST_MonitorData {
    std::string eventType;
    std::string filePath;
    std::string newHash;
    std::string oldHash;
    std::string timestamp;
    int64_t fileSize;
    std::string user;
    int processId;
};

class CDatabaseManager; //전방 선언

class CEventMonitor {
public:
    CEventMonitor();
    ~CEventMonitor();
    int StartMonitoring();

    // 이메일
    void SendEmailWithLogData(const std::string& logFilePath); 

    friend class EmailSender; 
private:
    int m_inotifyFd;
    std::unordered_map<int, std::string> m_mapWatchDescriptors;
    std::vector<std::string> m_vecWatchList;
    CDatabaseManager* m_dbManager;

    void readWatchList();
    void createInotifyInstance();
    void addWatchListToInotify();
    void addPathToInotify(const std::string& path);
    void runEventLoop();
    void processEvent(struct inotify_event *event);
    std::string CalculateFileHash(std::string filePath);
    void printEventsInfo(ST_MonitorData& data);
    void logEvent(ST_MonitorData& data);
    std::string getLogFilePath();
};
