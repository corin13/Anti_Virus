#pragma once

#define DETECT (200)
#define NOT_DETECT (201)

#define STAT_PID (0)
#define STAT_NAME (1)
#define STAT_PPID (3)

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
#include <unordered_set>

#include <openssl/sha.h>
#include <iomanip>

#include "error_codes.h"

class CAntiDebugger {
public:
    CAntiDebugger();
    ~CAntiDebugger();
    void Detect();   

private:
    std::string GetStatInfo(const std::string& strPath);   // /proc/[pid]/stat 파일 읽기
    std::vector<std::string> ParseStat(const std::string& strStat);   // /proc/[pid]/stat 데이터 파싱
    int CheckProcess();   // 실행 중인 프로세스를 확인하여 디버거 감지
    std::string GetName(); //현재 실행되는 내 프로그램의 이름 가져오기 ex: (UdkdAgent)
    std::string GetHash(const std::string& filePath); //md5로 해시하는 함수
    std::string mProcessName;
    std::string mGdbHash;
};
