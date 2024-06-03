#pragma once

#include <unordered_map>
#include <vector>
#include <string>
#include <sstream>
#include <sys/inotify.h>

struct MonitorData {
    std::string eventDescription;
    std::string filePath;
    std::string integrityResult;
    std::string newHash;
    std::string oldHash;
    std::string timestamp;
};

class CEventMonitor {
public:
    CEventMonitor();
    int StartMonitoring();

private:
    int m_inotifyFd;
    std::unordered_map<int, std::string> m_watchDescriptors;
    std::vector<std::string> m_watchList;

    std::vector<std::string> readWatchList(const std::string& watchListfilePath);
    void initializeWatchList();
    int createInotifyInstance();
    void addWatchListToInotify();
    void runEventLoop();
    void processEvent(struct inotify_event *event);
    void printEventsInfo(MonitorData& data);
    void verifyFileIntegrity(MonitorData& data);
    void logEvent(MonitorData& data);
    std::string getLogFilePath();
};
