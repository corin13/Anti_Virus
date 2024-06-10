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
    std::unordered_map<int, std::string> m_mapWatchDescriptors;
    std::vector<std::string> m_vecWatchList;

    void readWatchList();
    void initializeWatchList();
    void createInotifyInstance();
    void addWatchListToInotify();
    void runEventLoop();
    void processEvent(struct inotify_event *event);
    void printEventsInfo(MonitorData& data);
    void verifyFileIntegrity(MonitorData& data);
    void logEvent(MonitorData& data);
    std::string getLogFilePath();
};
