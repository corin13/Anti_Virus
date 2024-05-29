#pragma once

#include <unordered_map>

int StartMonitoring();
std::vector<std::string> ReadWatchList(const std::string& filePath);
void InitializeWatchList(const std::vector<std::string>& watchList);
int CreateInotifyInstance();
void AddWatchListToInotify(int inotifyFd, const std::vector<std::string>& watchList, std::unordered_map<int, std::string>& watchDescriptors);
void RunEventLoop(int inotifyFd, std::unordered_map<int, std::string>& watchDescriptors);
void ProcessEvent(struct inotify_event *event, std::unordered_map<int, std::string>& watchDescriptors);
void PrintEventsInfo(std::string eventDescription, const std::string &filePath);
void VerifyFileIntegrity(const std::string &filePath);