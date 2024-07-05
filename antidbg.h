#pragma once

#define DETECT (200)
#define NOT_DETECT (201)



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
};
