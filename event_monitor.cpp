#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sys/inotify.h>
#include <unistd.h>
#include "event_monitor.h"
#include "util.h"


int StartMonitoring() {
    std::string watchListFile = "watch_list.txt";
    
    // 감시할 파일 목록 읽기
    std::vector<std::string> watchList = ReadWatchList(watchListFile);
    
    // inotify 인스턴스 생성
    int inotifyFd = CreateInotifyInstance();
    
    // 감시 대상 추가
    AddWatchListToInotify(inotifyFd, watchList);

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

// inotify 인스턴스 생성 함수
int CreateInotifyInstance() {
    int inotifyFd = inotify_init();
    if (inotifyFd == -1) {
        HandleError(ERROR_INVALID_FUNCTION);
    }
    return inotifyFd;
}

// 파일 목록을 기반으로 inotify에 감시 대상 추가 함수
void AddWatchListToInotify(int inotifyFd, const std::vector<std::string>& watchList) {
    for (const auto& path : watchList) {
        int wd = inotify_add_watch(inotifyFd, path.c_str(), IN_MODIFY | IN_CREATE | IN_DELETE);
        if (wd == -1) {
            HandleError(ERROR_CANNOT_OPEN_DIRECTORY, path);
        } else {
            std::cout << "Watching " << path << "\n";
        }
    }
}