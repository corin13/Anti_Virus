#include "firewall.h"

int CFirewall::StartFirewall() {
    while (true) {
        int nOption =0;

        std::cout << "\nSelect Firewall Option \n\n"
                  << "1. Run Firewall \n"
                  << "2. Configure Firewall \n"
                  << "3. View Logs \n\n"
                  << "Please enter the option: ";

        std::string strInput;
        std::getline(std::cin, strInput);
        std::cout << std::endl;

        if (isValidNumber(strInput)) {
            nOption = std::stoi(strInput);
        }

        switch (nOption) {
            case 1:
                RunFirewall();
                break;
            case 2:
                ConfigureFirewall();
                break;
            case 3:
                ViewLogs();
                break;
            default:
                std::cerr << "Error: " << GetErrorMessage(ERROR_INVALID_OPTION) << std::endl;
                exit(ERROR_INVALID_OPTION);
                break;
        }
    }
    return SUCCESS_CODE;
}

int CFirewall::RunFirewall() {
    if (!FirewallConfig::Instance().Load(FIREWALL_INI_FILE)) {
        std::cerr << "Failed to load firewall rules in RunFirewall\n";
        return ERROR_INVALID_FUNCTION;
    }

    signal(SIGINT, handleExit);
    signal(SIGTERM, handleExit);

    auto& vecIniData = FirewallConfig::Instance().GetIniData();
    for (auto& stId : vecIniData) {
        std::vector<std::string> vecIniList;

        for (auto& stIdSecond : stId.second) {
            vecIniList.push_back(stIdSecond.second);
        }
        RunIptables(vecIniList[DIRECTION], vecIniList[IP], vecIniList[PORT], vecIniList[ACTION]);
    }

    CFirewall::ExecCommand("./firewall_logs.sh");

    return SUCCESS_CODE;
}

int CFirewall::ConfigureFirewall() {
    if (!FirewallConfig::Instance().Load(FIREWALL_INI_FILE)) {
        std::cerr << "Failed to load firewall rules in Configure\n";
        return ERROR_INVALID_FUNCTION;
    }

    int nStatusCode = SUCCESS_CODE;

    while (true) {
        std::string strInput;
        std::vector<std::string> vecWords;

        PrintConfigManual();

        std::getline(std::cin, strInput);
        std::cout << std::endl;

        if (strInput.empty()) {
            std::cerr << "Input cannot be only spaces." << std::endl;
            return ERROR_INVALID_INPUT;
        }

        vecWords = ConfigureUserInput(strInput);

        if (isValidInput(vecWords) != SUCCESS_CODE) {
            continue;
        }

        std::string strCmd = vecWords[COMMAND];

        if (strCmd == "a") {
            nStatusCode = AddRule(vecWords);
        } else if (strCmd == "u") {
            nStatusCode = UpdateRule(vecWords);
        } else if (strCmd == "d") {
            nStatusCode = DeleteRule(vecWords);
        } else if (strCmd == "l") {
            nStatusCode = RuleList();
        } else if (strCmd == "help") {
            nStatusCode = PrintFirewallHelp();
        } else if (strCmd == "exit") {
            nStatusCode = EXIT_CONFIG;
            break;
        }

        if (nStatusCode != SUCCESS_CODE) {
            break;
        }
    }

    return nStatusCode;
}

int CFirewall::ViewLogs() {
    std::vector<std::string> vecFilesPath;
    std::vector<std::string> vecFiles;
    int nNumber;
    int nCnt = 1;

    if (std::filesystem::exists(LOG_FILE_PATH)) {
        for (const auto& entry : std::filesystem::directory_iterator(LOG_FILE_PATH)) {
            if (std::filesystem::is_regular_file(entry.status())) {
                vecFilesPath.push_back(entry.path().string());
                vecFiles.push_back(entry.path().filename().string());
            }
        }
    } else {
        std::cerr << "ERROR: Cannot open file" << std::endl;
        return ERROR_CANNOT_OPEN_FILE;
    }

    VariadicTable<int, std::string> vt({"No", "Name"}, 10);

    for (const auto& strFile : vecFiles) {
        vt.addRow(nCnt, strFile);
        nCnt++;
    }

    vt.print(std::cout);

    std::cout << "\nPlease enter the number of the log file to read" << std::endl;
    std::cout << "NUMBER: ";
    
    std::string strInput;
    std::getline(std::cin, strInput);

    if (isValidNumber(strInput)) {
        nNumber = std::stoi(strInput);
    } else {
        PrintInputError(strInput);
        return ERROR_INVALID_INPUT;
    }

    if (nNumber < 1 || nNumber > vecFiles.size()) {
        PrintError("Invalid number");
        return ERROR_INVALID_INPUT;
    }

    std::string strCmd = "more " + vecFilesPath[nNumber - 1];

    system(strCmd.c_str());

    return SUCCESS_CODE;
}

int CFirewall::RunIptables(const std::string& strDirection, const std::string& strIp, const std::string& strPort, const std::string& strAction) {
    std::string strIptablesCmd = "iptables -A";
    std::string strIptablesLogCmd = "";
    std::string strErrCommand = " 2> /dev/null";

    if (strDirection == "INPUT") {
        strIptablesCmd += " INPUT ";
        strIptablesCmd += strIp == "ANY" ? "" : "-s " + strIp;
    } else if (strDirection == "OUTPUT") {
        strIptablesCmd += " OUTPUT ";
        strIptablesCmd += strIp == "ANY" ? "" : "-d " + strIp;
    } else {
        std::cerr << "Invalid Direction" << std::endl;
        return ERROR_INVALID_OPTION;
    }

    strIptablesCmd += strPort == "ANY" ? "" : " -p tcp --dport " + strPort;

    if (strAction == "DROP") {
        strIptablesLogCmd = strIptablesCmd + " -j LOG --log-prefix \"BLOCK \"";
        strIptablesCmd += " -j DROP";
    } else if (strAction == "ACCEPT") {
        strIptablesLogCmd = strIptablesCmd + " -j LOG --log-prefix \"ALLOW \"";
        strIptablesCmd += " -j ACCEPT";
    } else {
        std::cerr << "Invalid Action" << std::endl;
        return ERROR_INVALID_OPTION;
    }

    std::cout << strIptablesCmd << std::endl;

    CFirewall::ExecCommand(strIptablesLogCmd + strErrCommand);
    CFirewall::ExecCommand(strIptablesCmd + strErrCommand);

    return SUCCESS_CODE;
}

std::vector<std::string> CFirewall::ConfigureUserInput(std::string& strInput) {
    std::istringstream iss(strInput);
    std::vector<std::string> vecWords;
    std::string strWord;

    while (iss >> strWord) {
        std::transform(strWord.begin(), strWord.end(), strWord.begin(), ::tolower);

        strWord = (strWord == "add") ? "a" : (strWord == "update") ? "u" : (strWord == "delete") ? "d" : (strWord == "list") ? "l" : strWord;
        strWord = (strWord == "x" || strWord == "drop") ? "DROP" : (strWord == "o" || strWord == "accept") ? "ACCEPT" : strWord;
        strWord = (strWord == "to" || strWord == "output") ? "OUTPUT" : (strWord == "from" || strWord == "input") ? "INPUT" : strWord;
        strWord = (strWord == "any") ? "ANY" : strWord;

        vecWords.push_back(strWord);
    }

    if (vecWords[COMMAND] == "a") {
        if (vecWords.size() == ADD_MIN_LENGTH) {
            if (isValidIP(vecWords[ADD_IP])) {
                vecWords.emplace(vecWords.begin() + ADD_PORT, "ANY");
            } else if (isValidPort(vecWords[ADD_IP])) {
                vecWords.emplace(vecWords.begin() + ADD_IP, "ANY");
            }
        }
    }

    return vecWords;
}

int CFirewall::isValidInput(std::vector<std::string>& vecWords) {
    if (!FirewallConfig::Instance().Load(FIREWALL_INI_FILE)) {
        std::cerr << "Failed to load firewall rules in Configure\n";
        return ERROR_INVALID_FUNCTION;
    }
    auto& vecIniData = FirewallConfig::Instance().GetIniData();

    std::vector<std::string> vecDirectionWords = {"INPUT", "OUTPUT"};
    std::vector<std::string> vecActionWords = {"DROP", "ACCEPT"};

    std::string strCommand = vecWords[COMMAND];

    if (strCommand == "a") {
        if (!(vecWords.size() == ADD_MIN_LENGTH || vecWords.size() == ADD_MAX_LENGTH)) {
            std::cerr << "Invalid length input." << std::endl;
            return ERROR_INVALID_INPUT;
        }

        if (std::find(vecDirectionWords.begin(), vecDirectionWords.end(), vecWords[ADD_DIRECTION]) == vecDirectionWords.end()) {
            PrintInputError(vecWords[ADD_DIRECTION]);
            return ERROR_INVALID_INPUT;
        }
        if (!isValidIP(vecWords[ADD_IP])) {
            PrintInputError(vecWords[ADD_IP]);
            return ERROR_INVALID_INPUT;
        }
        if (!isValidPort(vecWords[ADD_PORT])) {
            PrintInputError(vecWords[ADD_PORT]);
            return ERROR_INVALID_INPUT;
        }
        if (std::find(vecActionWords.begin(), vecActionWords.end(), vecWords[ADD_ACTION]) == vecActionWords.end()) {
            PrintInputError(vecWords[ADD_ACTION]);
            return ERROR_INVALID_INPUT;
        }

        return SUCCESS_CODE;
    } else if (strCommand == "u") {
        if (vecWords.size() != UPDATE_LENGTH) {
            std::cerr << "Invalid length input." << std::endl;
            return ERROR_INVALID_INPUT;
        }

        if (!isValidNumber(vecWords[UPDATE_NUMBER])) {
            PrintInputError(vecWords[UPDATE_NUMBER]);
            return ERROR_INVALID_INPUT;
        }

        int nUpdateNum = std::stoi(vecWords[UPDATE_NUMBER]);

        if (vecIniData.size() < nUpdateNum || nUpdateNum < 1) {
            PrintInputError(vecWords[UPDATE_NUMBER]);
            return ERROR_INVALID_INPUT;
        }

        if (vecWords[UPDATE_REDIRECTION] != ">") {
            PrintInputError(vecWords[UPDATE_REDIRECTION]);
            return ERROR_INVALID_INPUT;
        }

        if (vecWords[UPDATE_OPTION] == "direction") {
            if (std::find(vecDirectionWords.begin(), vecDirectionWords.end(), vecWords[UPDATE_NEW_VALUE]) == vecDirectionWords.end()) {
                PrintInputError(vecWords[UPDATE_NEW_VALUE]);
                return ERROR_INVALID_INPUT;
            }
        } else if (vecWords[UPDATE_OPTION] == "ip") {
            if (!isValidIP(vecWords[UPDATE_NEW_VALUE])) {
                PrintInputError(vecWords[UPDATE_NEW_VALUE]);
                return ERROR_INVALID_INPUT;
            }
        } else if (vecWords[UPDATE_OPTION] == "port") {
            if (!isValidPort(vecWords[UPDATE_NEW_VALUE])) {
                PrintInputError(vecWords[UPDATE_NEW_VALUE]);
                return ERROR_INVALID_INPUT;
            }
        } else if (vecWords[UPDATE_OPTION] == "action") {
            if (std::find(vecActionWords.begin(), vecActionWords.end(), vecWords[UPDATE_NEW_VALUE]) == vecActionWords.end()) {
                PrintInputError(vecWords[UPDATE_NEW_VALUE]);
                return ERROR_INVALID_INPUT;
            }
        } else {
            PrintInputError(vecWords[UPDATE_NEW_VALUE]);
            return ERROR_INVALID_INPUT;
        }

        return SUCCESS_CODE;
    } else if (strCommand == "d") {
        if (vecWords.size() != DELETE_LENGTH) {
            std::cerr << "Invalid length input." << std::endl;
            return ERROR_INVALID_INPUT;
        }

        if (vecWords[DELETE_NUMBER] == "all") {
            return SUCCESS_CODE;
        }

        if (!isValidNumber(vecWords[DELETE_NUMBER])) {
            PrintInputError(vecWords[DELETE_NUMBER]);
            return ERROR_INVALID_INPUT;
        }

        int nDelNum = std::stoi(vecWords[DELETE_NUMBER]);

        if (vecIniData.size() < nDelNum || nDelNum < 1) {
            PrintInputError(vecWords[DELETE_NUMBER]);
            return ERROR_INVALID_INPUT;
        }

        return SUCCESS_CODE;
    } else if (strCommand == "l") {
        if (vecWords.size() != 1) {
            std::cerr << "Invalid Input" << std::endl;
            return ERROR_INVALID_INPUT;
        }
        return SUCCESS_CODE;
    } else if (strCommand == "exit" || strCommand == "help") {
        return SUCCESS_CODE;
    } else {
        PrintInputError(strCommand);
        return ERROR_INVALID_INPUT;
    }

    return ERROR_UNKNOWN;
}

int CFirewall::AddRule(std::vector<std::string>& vecWords) {
    try {
        FirewallConfig::Instance().AddRule(vecWords[ADD_DIRECTION], vecWords[ADD_IP], vecWords[ADD_PORT], vecWords[ADD_ACTION]);
        std::cout << "Rule successfully added\n" << std::endl;
        return SUCCESS_CODE;
    } 
    catch (std::exception& e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
        return ERROR_UNKNOWN;
    }
}

int CFirewall::UpdateRule(std::vector<std::string>& vecWords) {
    if (!FirewallConfig::Instance().Load(FIREWALL_INI_FILE)) {
        std::cerr << "Failed to load firewall rules in Configure\n";
        return ERROR_INVALID_FUNCTION;
    }

    try {
        auto& vecIniData = FirewallConfig::Instance().GetIniData();
        std::string strSectionName = GetSectionName(vecIniData, std::stoi(vecWords[UPDATE_NUMBER]));
        FirewallConfig::Instance().UpdateRule(strSectionName, vecWords[UPDATE_OPTION], vecWords[UPDATE_NEW_VALUE]);

        std::cout << "Rule successfully updated\n" << std::endl;
        return SUCCESS_CODE;
    } 
    catch (std::exception& e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
        return ERROR_UNKNOWN;
    }
}

int CFirewall::DeleteRule(std::vector<std::string>& vecWords) {
    if (!FirewallConfig::Instance().Load(FIREWALL_INI_FILE)) {
        std::cerr << "Failed to load firewall rules in Configure\n";
        return ERROR_INVALID_FUNCTION;
    }

    auto vecIniData = FirewallConfig::Instance().GetIniData();
    std::string strSectionName = (vecWords[DELETE_NUMBER] == "all") ? "all" : GetSectionName(vecIniData, std::stoi(vecWords[DELETE_NUMBER]));
    FirewallConfig::Instance().DeleteRule(strSectionName);

    std::cout << "Rule successfully deleted\n" << std::endl;
    return SUCCESS_CODE;
}

int CFirewall::RuleList() {
    if (!FirewallConfig::Instance().Load(FIREWALL_INI_FILE)) {
        std::cerr << "Failed to load firewall rules in Configure\n";
        return ERROR_INVALID_FUNCTION;
    }
    VariadicTable<int, std::string, std::string, std::string, std::string> vt({"No", "Direction", "IP Address", "PORT", "Action"}, 10);

    auto vecIniData = FirewallConfig::Instance().GetIniData();
    int nRuleNumber = 0;

    for (const auto& stId : vecIniData) {
        nRuleNumber++;
        std::vector<std::string> vecDataFormat;

        for (const auto& stSd : stId.second) {
            vecDataFormat.push_back(stSd.second);
        }
        vt.addRow(nRuleNumber, vecDataFormat[DIRECTION], vecDataFormat[IP], vecDataFormat[PORT], vecDataFormat[ACTION]);
    }

    vt.print(std::cout);

    return SUCCESS_CODE;
}

void CFirewall::PrintConfigManual() {
    std::cout << COLOR_BLUE "[ADD]    : " COLOR_RESET " [A/add] [TO/FROM] [IP] [PORT] [ACCEPT(o)/DROP(x)] \n"
              << COLOR_GREEN "[UPDATE] : " COLOR_RESET " [U/update] [Rule Number] [OPTION] [>] [Change Value]\n"
              << COLOR_RED "[DELETE] : " COLOR_RESET " [D/delete] [Rule Number] \n"
              << COLOR_YELLOW "[LIST]   : " COLOR_RESET " [L/list] \n\n"
              << COLOR_CYAN "[EXIT]" COLOR_RESET COLOR_MAGENTA "[HELP]" COLOR_RESET "\n\n"
              << "COMMAND: ";
}

void CFirewall::handleExit(int nSignum) {
    std::cout << "\nProgram is terminating\n" << std::endl;
    std::vector<std::string> vecCmdList = {"iptables -F", "pkill -f firewall_logs.sh"};
    for (const std::string& strCmd : vecCmdList) {
        CFirewall::ExecCommand(strCmd);
    }

    exit(nSignum);
}

void CFirewall::ExecCommand(const std::string& strCmd) {
    FILE* pPipe = popen(strCmd.c_str(), "r");
    if (!pPipe) {
        std::cerr << "ERROR: popen() failed" << std::endl;
        return;
    }

    char chBuffer[128];
    while (fgets(chBuffer, sizeof(chBuffer), pPipe) != nullptr) {
        std::cout << chBuffer;
    }

    pclose(pPipe);
}

std::string CFirewall::GetSectionName(const auto& vecIniData, int nNumber) {
    int nCnt = 1;
    for (const auto& stId : vecIniData) {
        if (nNumber == nCnt) {
            return stId.first;
        } else {
            nCnt++;
        }
    }

    return "";
}

bool CFirewall::isValidIP(const std::string& strIp) {
    std::regex stIpPattern("^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\."
                         "(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\."
                         "(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\."
                         "(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$");

    return std::regex_match(strIp, stIpPattern) || strIp == "ANY";
}

bool CFirewall::isValidPort(const std::string& strPort) {
    std::regex stPortPattern("^(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}|0)$");
    return std::regex_match(strPort, stPortPattern) || strPort == "ANY";
}

bool CFirewall::isValidNumber(const std::string& strNumber) {
    std::istringstream iss(strNumber);
    int nNum;

    return (iss >> nNum) && (iss.eof());
}

int CFirewall::PrintFirewallHelp() {
    std::cout << "A, add     - Rule Add Command\n"
              << "             - [TO]    : Settings for outgoing packets\n"
              << "             - [FROM]  : Settings for incoming packets\n"
              << "             - [DROP]  : Packet blocking settings\n"
              << "             - [ACCEPT]: Packet allow settings\n\n"
              << "U, update  - Rule Update Command\n"
              << "             - [Rule Number]  : Rule Index Number\n"
              << "             - [OPTION]       : The title of the value you want to change\n"
              << "             - [>]            : Must use '>' \n"
              << "             - [Change Value] : Value to change\n\n"
              << "D, delete  - Rule Delete Command\n"
              << "             - [Rule Number] : Rule Index Number\n\n"
              << "L, list    - Rule Inquiry Command\n\n"
              << "EXIT       - End Rule Set Commands\n"
              << std::endl;
    return SUCCESS_CODE;
}
