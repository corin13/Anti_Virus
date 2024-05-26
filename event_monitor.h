#pragma once

int StartMonitoring();
std::vector<std::string> ReadWatchList(const std::string& filePath);
int CreateInotifyInstance();
void AddWatchListToInotify(int inotifyFd, const std::vector<std::string>& watchList);
