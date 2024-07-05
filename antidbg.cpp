    #include "antidbg.h"


CAntiDebugger::CAntiDebugger() {}
CAntiDebugger::~CAntiDebugger() {}

std::string CAntiDebugger::GetStatInfo(const std::string& strPath) {
    std::string strStatPath = strPath + "/stat";
    std::ifstream ifsStatFile(strStatPath);
    if (!ifsStatFile.is_open()) {
        throw std::runtime_error("File: " + strStatPath);
    }

    std::string strStat((std::istreambuf_iterator<char>(ifsStatFile)), std::istreambuf_iterator<char>());

    ifsStatFile.close();
    return strStat;
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
                std::string strPid = vecStatParse[0];
                std::string strName = vecStatParse[1];
                std::string strPpid = vecStatParse[3];

                if (strName == "(gdb)") {
                    setDbgPids.insert(strPid);
                } else if (strName == "(UdkdAgent)") {
                    vecUdkdPids.emplace_back(strPid, strPpid);
                }
            }
            else{
                std::cerr << "ERROR" <<std::endl;
                return ERROR_UNKNOWN;
            }
        }
    }
    closedir(pDir);

    for (auto& [strPid, strPpid] : vecUdkdPids) {
        if (setDbgPids.find(strPpid) != setDbgPids.end()) {
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
