#include "firewall.h"

int CFirewall::StartFirewall() {
    while (true) {
        int option = -1;
        int status;
        std::cout << "\nSelect Firewall Option \n\n"
                  << "1. Run Firewall \n"
                  << "2. Configure Firewall \n"
                  << "3. View Logs \n\n"
                  << "Please enter the option: ";

        std::string input;
        std::getline(std::cin, input);
        std::cout << std::endl;

        if (isValidNumber(input)) {
            option = std::stoi(input);
        }

        switch (option) {
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
    if (!FirewallConfig::Instance().Load("firewall_rules.ini")) {
        std::cerr << "Failed to load firewall rules in RunFirewall\n";
        return ERROR_INVALID_FUNCTION;
    }

    signal(SIGINT, handleExit);
    signal(SIGTERM, handleExit);

    auto& iniData = FirewallConfig::Instance().GetIniData();
    for (auto& id : iniData) {
        std::vector<std::string> iniList;

        for (auto& idSecond : id.second) {
            iniList.push_back(idSecond.second);
        }
        RunIptables(iniList[DIRECTION], iniList[IP], iniList[PORT], iniList[ACTION]);
    }

    CFirewall::ExecCommand("./firewall_logs.sh");

    return SUCCESS_CODE;
}

int CFirewall::ConfigureFirewall() {
    if (!FirewallConfig::Instance().Load("firewall_rules.ini")) {
        std::cerr << "Failed to load firewall rules in Configure\n";
        return ERROR_INVALID_FUNCTION;
    }

    int statusCode = SUCCESS_CODE;

    while (true) {
        std::string input;
        std::vector<std::string> words;

        PrintConfigManual();

        std::getline(std::cin, input);
        std::cout << std::endl;

        if (input.empty()) {
            std::cerr << "Input cannot be only spaces." << std::endl;
            return ERROR_INVALID_INPUT;
        }

        words = ConfigureUserInput(input);

        if (isValidInput(words) != SUCCESS_CODE) {
            continue;
        }

        std::string cmd = words[COMMAND];

        if (cmd == "a") {
            statusCode = AddRule(words);
        } else if (cmd == "u") {
            statusCode = UpdateRule(words);
        } else if (cmd == "d") {
            statusCode = DeleteRule(words);
        } else if (cmd == "l") {
            statusCode = RuleList();
        } else if (cmd == "help") {
            statusCode = PrintFirewallHelp();
        } else if (cmd == "exit") {
            statusCode = EXIT_CONFIG;
            break;
        }

        if (statusCode != SUCCESS_CODE) {
            break;
        }
    }

    return statusCode;
}

int CFirewall::ViewLogs() {
    std::vector<std::string> filesPath;
    std::vector<std::string> files;
    int number;
    int cnt = 1;

    if (std::filesystem::exists(LOG_FILE_PATH)) {
        for (const auto& entry : std::filesystem::directory_iterator(LOG_FILE_PATH)) {
            if (std::filesystem::is_regular_file(entry.status())) {
                filesPath.push_back(entry.path().string());
                files.push_back(entry.path().filename().string());
            }
        }
    } else {
        std::cerr << "ERROR: Cannot open file" << std::endl;
        return ERROR_CANNOT_OPEN_FILE;
    }

    VariadicTable<int, std::string> vt({"No", "Name"}, 10);

    for (const auto& file : files) {
        vt.addRow(cnt, file);
        cnt++;
    }

    vt.print(std::cout);

    std::cout << "\nPlease enter the number of the log file to read" << std::endl;
    std::cout << "NUMBER: ";
    
    std::string input;
    std::getline(std::cin, input);

    if (isValidNumber(input)) {
        number = std::stoi(input);
    } else {
        PrintInputError(input);
        return ERROR_INVALID_INPUT;
    }

    if (number < 1 || number > files.size()) {
        PrintError("Invalid number");
        return ERROR_INVALID_INPUT;
    }

    std::string cmd = "more " + filesPath[number - 1];

    system(cmd.c_str());

    return SUCCESS_CODE;
}

int CFirewall::RunIptables(const std::string& direction, const std::string& ip, const std::string& port, const std::string& action) {
    std::string iptablesCmd = "iptables -A";
    std::string iptablesLogCmd = "";
    std::string errCommand = " 2> /dev/null";

    if (direction == "INPUT") {
        iptablesCmd += " INPUT ";
        iptablesCmd += ip == "ANY" ? "" : "-s " + ip;
    } else if (direction == "OUTPUT") {
        iptablesCmd += " OUTPUT ";
        iptablesCmd += ip == "ANY" ? "" : "-d " + ip;
    } else {
        std::cerr << "Invalid Direction" << std::endl;
        return ERROR_INVALID_OPTION;
    }

    iptablesCmd += port == "ANY" ? "" : " -p tcp --dport " + port;

    if (action == "DROP") {
        iptablesLogCmd = iptablesCmd + " -j LOG --log-prefix \"BLOCK \"";
        iptablesCmd += " -j DROP";
    } else if (action == "ACCEPT") {
        iptablesLogCmd = iptablesCmd + " -j LOG --log-prefix \"ALLOW \"";
        iptablesCmd += " -j ACCEPT";
    } else {
        std::cerr << "Invalid Action" << std::endl;
        return ERROR_INVALID_OPTION;
    }

    std::cout << iptablesCmd << std::endl;


    CFirewall::ExecCommand(iptablesLogCmd+errCommand);
    CFirewall::ExecCommand(iptablesCmd+errCommand);

    return SUCCESS_CODE;
}

std::vector<std::string> CFirewall::ConfigureUserInput(std::string& input) {
    std::istringstream iss(input);
    std::vector<std::string> words;
    std::string word;

    while (iss >> word) {
        std::transform(word.begin(), word.end(), word.begin(), ::tolower);

        word = (word == "add") ? "a" : (word == "update") ? "u" : (word == "delete") ? "d" : (word == "list") ? "l" : word;
        word = (word == "x" || word == "drop") ? "DROP" : (word == "o" || word == "accept") ? "ACCEPT" : word;
        word = (word == "to" || word == "output") ? "OUTPUT" : (word == "from" || word == "input") ? "INPUT" : word;
        word = (word == "any") ? "ANY" : word;

        words.push_back(word);
    }

    if (words[COMMAND] == "a") {
        if (words.size() == ADD_MIN_LENGTH) {
            if (isValidIP(words[ADD_IP])) {
                words.emplace(words.begin() + ADD_PORT, "ANY");
            } else if (isValidPort(words[ADD_IP])) {
                words.emplace(words.begin() + ADD_IP, "ANY");
            }
        }
    }

    return words;
}

int CFirewall::isValidInput(std::vector<std::string>& words) {
    if (!FirewallConfig::Instance().Load("firewall_rules.ini")) {
        std::cerr << "Failed to load firewall rules in Configure\n";
        return ERROR_INVALID_FUNCTION;
    }
    auto& iniData = FirewallConfig::Instance().GetIniData();

    std::vector<std::string> directionWords = {"INPUT", "OUTPUT"};
    std::vector<std::string> actionWords = {"DROP", "ACCEPT"};

    std::string command = words[COMMAND];

    if (command == "a") {
        if (!(words.size() == ADD_MIN_LENGTH || words.size() == ADD_MAX_LENGTH)) {
            std::cerr << "Invalid length input." << std::endl;
            return ERROR_INVALID_INPUT;
        }

        if (std::find(directionWords.begin(), directionWords.end(), words[ADD_DIRECTION]) == directionWords.end()) {
            PrintInputError(words[ADD_DIRECTION]);
            return ERROR_INVALID_INPUT;
        }
        if (!isValidIP(words[ADD_IP])) {
            PrintInputError(words[ADD_IP]);
            return ERROR_INVALID_INPUT;
        }
        if (!isValidPort(words[ADD_PORT])) {
            PrintInputError(words[ADD_PORT]);
            return ERROR_INVALID_INPUT;
        }
        if (std::find(actionWords.begin(), actionWords.end(), words[ADD_ACTION]) == actionWords.end()) {
            PrintInputError(words[ADD_ACTION]);
            return ERROR_INVALID_INPUT;
        }

        return SUCCESS_CODE;
    } else if (command == "u") {
        if (words.size() != UPDATE_LENGTH) {
            std::cerr << "Invalid length input." << std::endl;
            return ERROR_INVALID_INPUT;
        }

        if (!isValidNumber(words[UPDATE_NUMBER])) {
            PrintInputError(words[UPDATE_NUMBER]);
            return ERROR_INVALID_INPUT;
        }

        int updateNum = std::stoi(words[UPDATE_NUMBER]);

        if (iniData.size() < updateNum || updateNum < 1) {
            PrintInputError(words[UPDATE_NUMBER]);
            return ERROR_INVALID_INPUT;
        }

        if (words[UPDATE_REDIRECTION] != ">") {
            PrintInputError(words[UPDATE_REDIRECTION]);
            return ERROR_INVALID_INPUT;
        }

        if (words[UPDATE_OPTION] == "direction") {
            if (std::find(directionWords.begin(), directionWords.end(), words[UPDATE_NEW_VALUE]) == directionWords.end()) {
                PrintInputError(words[UPDATE_NEW_VALUE]);
                return ERROR_INVALID_INPUT;
            }
        } else if (words[UPDATE_OPTION] == "ip") {
            if (!isValidIP(words[UPDATE_NEW_VALUE])) {
                PrintInputError(words[UPDATE_NEW_VALUE]);
                return ERROR_INVALID_INPUT;
            }
        } else if (words[UPDATE_OPTION] == "port") {
            if (!isValidPort(words[UPDATE_NEW_VALUE])) {
                PrintInputError(words[UPDATE_NEW_VALUE]);
                return ERROR_INVALID_INPUT;
            }
        } else if (words[UPDATE_OPTION] == "action") {
            if (std::find(actionWords.begin(), actionWords.end(), words[UPDATE_NEW_VALUE]) == actionWords.end()) {
                PrintInputError(words[UPDATE_NEW_VALUE]);
                return ERROR_INVALID_INPUT;
            }
        } else {
            PrintInputError(words[UPDATE_NEW_VALUE]);
            return ERROR_INVALID_INPUT;
        }

        return SUCCESS_CODE;
    } else if (command == "d") {
        if (words.size() != DELETE_LENGTH) {
            std::cerr << "Invalid length input." << std::endl;
            return ERROR_INVALID_INPUT;
        }

        if (words[DELETE_NUMBER] == "all") {
            return SUCCESS_CODE;
        }

        if (!isValidNumber(words[DELETE_NUMBER])) {
            PrintInputError(words[DELETE_NUMBER]);
            return ERROR_INVALID_INPUT;
        }

        int delNum = std::stoi(words[DELETE_NUMBER]);

        if (iniData.size() < delNum || delNum < 1) {
            PrintInputError(words[DELETE_NUMBER]);
            return ERROR_INVALID_INPUT;
        }

        return SUCCESS_CODE;
    } else if (command == "l") {
        if (words.size() != 1) {
            std::cerr << "Invalid Input" << std::endl;
            return ERROR_INVALID_INPUT;
        }
        return SUCCESS_CODE;
    } else if (command == "exit" || command == "help") {
        return SUCCESS_CODE;
    } else {
        PrintInputError(command);
        return ERROR_INVALID_INPUT;
    }

    return ERROR_UNKNOWN;
}

int CFirewall::AddRule(std::vector<std::string>& words) {
    try {
        FirewallConfig::Instance().AddRule(words[ADD_DIRECTION], words[ADD_IP], words[ADD_PORT], words[ADD_ACTION]);
        std::cout << "Rule successfully added\n" << std::endl;
        return SUCCESS_CODE;
    } catch (std::exception& e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
        return ERROR_UNKNOWN;
    }
}

int CFirewall::UpdateRule(std::vector<std::string>& words) {
    if (!FirewallConfig::Instance().Load("firewall_rules.ini")) {
        std::cerr << "Failed to load firewall rules in Configure\n";
        return ERROR_INVALID_FUNCTION;
    }

    try {
        auto& iniData = FirewallConfig::Instance().GetIniData();
        std::string sectionName = GetSectionName(iniData, std::stoi(words[UPDATE_NUMBER]));
        FirewallConfig::Instance().UpdateRule(sectionName, words[UPDATE_OPTION], words[UPDATE_NEW_VALUE]);

        std::cout << "Rule successfully updated\n" << std::endl;
        return SUCCESS_CODE;
    } catch (std::exception& e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
        return ERROR_UNKNOWN;
    }
}

int CFirewall::DeleteRule(std::vector<std::string>& words) {
    if (!FirewallConfig::Instance().Load("firewall_rules.ini")) {
        std::cerr << "Failed to load firewall rules in Configure\n";
        return ERROR_INVALID_FUNCTION;
    }

    auto iniData = FirewallConfig::Instance().GetIniData();
    std::string sectionName = (words[DELETE_NUMBER] == "all") ? "all" : GetSectionName(iniData, std::stoi(words[DELETE_NUMBER]));
    FirewallConfig::Instance().DeleteRule(sectionName);

    std::cout << "Rule successfully deleted\n" << std::endl;
    return SUCCESS_CODE;
}

int CFirewall::RuleList() {
    if (!FirewallConfig::Instance().Load("firewall_rules.ini")) {
        std::cerr << "Failed to load firewall rules in Configure\n";
        return ERROR_INVALID_FUNCTION;
    }
    VariadicTable<int, std::string, std::string, std::string, std::string> vt({"No", "Direction", "IP Address", "PORT", "Action"}, 10);

    auto iniData = FirewallConfig::Instance().GetIniData();
    int ruleNumber = 0;

    for (const auto& id : iniData) {
        ruleNumber++;
        std::vector<std::string> dataFormat;

        for (const auto& sd : id.second) {
            dataFormat.push_back(sd.second);
        }
        vt.addRow(ruleNumber, dataFormat[DIRECTION], dataFormat[IP], dataFormat[PORT], dataFormat[ACTION]);
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

void CFirewall::handleExit(int signum) {
    std::cout << "\nProgram is terminating\n" << std::endl;
    std::vector<std::string> cmdList = {"iptables -F", "pkill -f firewall_logs.sh"};
    for (const std::string& cmd : cmdList) {
        CFirewall::ExecCommand(cmd);
    }

    exit(signum);
}

void CFirewall::ExecCommand(const std::string& cmd) {
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        std::cerr << "ERROR: popen() failed" << std::endl;
        return;
    }

    char buffer[128];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        std::cout << buffer;
    }

    pclose(pipe);
}

std::string CFirewall::GetSectionName(const auto& iniData, int number) {
    int cnt = 1;
    for (const auto& id : iniData) {
        if (number == cnt) {
            return id.first;
        } else {
            cnt++;
        }
    }

    return "";
}

bool CFirewall::isValidIP(const std::string& ip) {
    std::regex ipPattern("^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\."
                         "(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\."
                         "(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\."
                         "(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$");

    return std::regex_match(ip, ipPattern) || ip == "ANY";
}

bool CFirewall::isValidPort(const std::string& port) {
    std::regex portPattern("^(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}|0)$");
    return std::regex_match(port, portPattern) || port == "ANY";
}

bool CFirewall::isValidNumber(const std::string& number) {
    std::istringstream iss(number);
    int num;

    return (iss >> num) && (iss.eof());
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

void CFirewall::SendEmailWithFireWallLogData(const std::string& logFilePath) {
    LogParser logParser;
    auto logData = logParser.ParseFirewallLog(logFilePath);

    if (logData.empty()) {
        std::cerr << "Failed to parse log file." << std::endl;
        return;
    }

    std::string emailBody =
        "[Alert] 일간 방화벽 로그 요약 보고서\n\n"
        "안녕하세요,\n"
        "아래는 하루 동안의 방화벽 로그 요약 보고서 입니다.\n\n"
        "[요약 보고서]\n"
        "날짜: " + logData["날짜"] + "\n"
        "총 이벤트 수: " + logData["총 이벤트 수"] + "\n"
        "허용된 트래픽: " + logData["허용된 트래픽"] + "건\n"
        "차단된 트래픽: " + logData["차단된 트래픽"] + "건\n\n"
        "[연락처 정보]\n"
        "시스템 관리자: 이름 (이메일, 전화번호)\n\n"
        "감사합니다.\n";

    std::string subject = "일간 방화벽 로그 요약 보고서";

    std::string recipientEmailAddress = Config::Instance().GetEmailAddress();
    if (!recipientEmailAddress.empty()) {
        EmailSender emailSender("smtps://smtp.gmail.com", 465, recipientEmailAddress);
        if (emailSender.SendEmailWithAttachment(subject, emailBody, logFilePath) == 0) {
            std::cout << "\n" << COLOR_GREEN << "Email sent successfully." << COLOR_RESET << "\n";
        } else {
            std::cerr << "Failed to send email." << std::endl;
        }
    } else {
        std::cerr << "Email address is not configured.\n";
    }
}
