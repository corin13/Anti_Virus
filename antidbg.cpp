#include "antidbg.h"

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
    std::vector<unsigned char> vecHash(SHA256_DIGEST_LENGTH);

    std::ifstream ifs(filePath, std::ifstream::binary);
    
    if (!ifs) {
        throw std::runtime_error("Failed to open file: " + filePath);
    }

    SHA256_CTX sha256Context;
    SHA256_Init(&sha256Context);

    std::vector<char> vecBuffer(1024);
    
    while (ifs.good()) {
        ifs.read(vecBuffer.data(), vecBuffer.size());
        SHA256_Update(&sha256Context, vecBuffer.data(), ifs.gcount());
    }
    ifs.close();

    SHA256_Final(vecHash.data(), &sha256Context);

    std::ostringstream oss;
    for(const auto& byte : vecHash) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return oss.str();

}



