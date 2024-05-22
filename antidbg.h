#pragma once

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <signal.h>
#include <dirent.h>
#include <algorithm>
#include <unistd.h>
#include <memory>

// /proc/[pid]/stat 파일을 읽어오는 함수 (/proc/[pid] 까지의 경로를 받아옴))
std::string GetStatInfo(const std::string& path);

// GetStatInfo 함수를 통해 읽어온 데이터를 파싱하고 vector에 저장하는 함수 (/proc/[pid]/stat 파일의 데이터를 문자열로 받아옴)
std::vector<std::string> ParseStat(const std::string& stat);

// 실행중인 프로세스를 확인하여 디버거를 탐지하는 함수
int CheckProcess();


void Detect();
