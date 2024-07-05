#include "antidbg.h"

/*
수정해야 할 것들
1. 변수명, 함수명 제대로 짓기
2. 변수명 코딩 컨벤션 맞추기
3. 시간 되면 파일 오픈, exe파일 해시 할 때 검증 절차 추가
*/

CAntiDebugger::CAntiDebugger() {
    mProcessName = GetName();
    mGdbHash = GetHash("/usr/bin/gdb");
}

CAntiDebugger::~CAntiDebugger() {}

std::string CAntiDebugger::GetStatInfo(const std::string& strPath) {
    std::string strStatPath = strPath + "/stat";
    
    try {
        std::ifstream ifsStatFile(strStatPath);
        std::string strStat((std::istreambuf_iterator<char>(ifsStatFile)), std::istreambuf_iterator<char>());

        ifsStatFile.close();
        return strStat;
    }
    catch(std::runtime_error e){
        std::cerr << e.what() << std::endl;
    }
}


std::vector<std::string> CAntiDebugger::ParseStat(const std::string& strStat) {
    std::istringstream issStrStat(strStat);
    std::vector<std::string> vecTokens;
    std::string strToken;

    while (issStrStat >> strToken) {
        vecTokens.push_back(strToken);
    }
    return vecTokens;
}

int CAntiDebugger::CheckProcess() {
    DIR* pDir;
    struct dirent* pEntry;
    std::unordered_set<std::string> setDbgPids;
    std::vector<std::pair<std::string, std::string>> vecUdkdPids;
    
    if ((pDir = opendir("/proc")) == nullptr) {
        return ERROR_CANNOT_OPEN_DIRECTORY;
    }

    while ((pEntry = readdir(pDir)) != nullptr) {
        if (pEntry->d_type == DT_DIR && std::string(pEntry->d_name).find_first_not_of("0123456789") == std::string::npos) {
            std::string strPath = "/proc/" + std::string(pEntry->d_name);
            std::string strStat;

            try {
                strStat = GetStatInfo(strPath);
            } 
            catch (const std::exception& e) {
                std::cerr << e.what() << std::endl;
                closedir(pDir);
                return ERROR_CANNOT_OPEN_FILE;
            }

            auto vecStatParse = ParseStat(strStat);

            if (vecStatParse.size() > 3) {
                std::string strPid = vecStatParse[STAT_PID];
                std::string strName = vecStatParse[STAT_NAME];
                std::string strPpid = vecStatParse[STAT_PPID];

                if (strName == mProcessName) {
                    vecUdkdPids.emplace_back(strPid, strPpid);
                }
            }
            else{
                std::cerr << "ERROR" <<std::endl;
                closedir(pDir);
                return ERROR_UNKNOWN;
            }
        }
    }
    closedir(pDir);

    for (auto& [strPid, strPpid] : vecUdkdPids) {
        std::string strPpidExeHash =  GetHash("/proc/"+strPpid+"/exe");
        if (strPpidExeHash == mGdbHash){
            kill(std::stoi(strPid), SIGTERM);
            return DETECT;
        }        
    }
    return NOT_DETECT;

}

void CAntiDebugger::Detect() {
    std::cout << "Process started. The system is now protected against debugging attempts." << std::endl;


    while (true) {

        int nStateCode = CheckProcess();

        if (nStateCode == DETECT) {
            std::cout << "Debugger detected! Terminating program" << std::endl;
        } else if (nStateCode == NOT_DETECT) {
            std::cout << "Anti-debugging Logic Running…" << std::endl;
        } else {
            std::cout << GetErrorMessage(nStateCode) << std::endl;
            exit(nStateCode);
        }

        sleep(3);
    }
    
}


std::string CAntiDebugger::GetName(){
    pid_t pidUdkd = getpid();
    std::string strPath = "/proc/" + std::to_string(pidUdkd);
    std::string strStat = GetStatInfo(strPath);

    std::vector<std::string> vecParseStat = ParseStat(strStat);

    return vecParseStat[STAT_NAME];
}


std::string CAntiDebugger::GetHash(const std::string& filePath) {
    // 해시 값을 저장할 벡터를 생성해요.
    std::vector<unsigned char> vecHash(SHA256_DIGEST_LENGTH);

    // 파일을 바이너리 모드로 열어요.
    std::ifstream ifs(filePath, std::ifstream::binary);
    
    // 파일을 열지 못하면 예외를 발생시켜요.
    if (!ifs) {
        throw std::runtime_error("Failed to open file: " + filePath);
    }

    // SHA-256 컨텍스트를 초기화해요.
    SHA256_CTX sha256Context;
    SHA256_Init(&sha256Context);

    // 데이터를 읽어올 버퍼를 생성해요.
    std::vector<char> vecBuffer(1024);
    
    // 파일을 끝까지 읽어요.
    while (ifs.good()) {
        ifs.read(vecBuffer.data(), vecBuffer.size());
        SHA256_Update(&sha256Context, vecBuffer.data(), ifs.gcount());
    }
    ifs.close();

    // 최종 SHA-256 해시 값을 계산해요.
    SHA256_Final(vecHash.data(), &sha256Context);

    // 해시 값을 16진수 문자열로 변환해요.
    std::ostringstream oss;
    for(const auto& byte : vecHash) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return oss.str();

}



