#define ERROR_INVALID_INPUT (200)

#include "firewall.h"
#include "config_firewall.h"
#include "VariadicTable.h"


int Firewall() {
    int option = 0;

    while (true) {
        std::cout <<
            "Select Firewall Option \n\n"
            "1. Run Firewall \n"
            "2. Configure Firewall \n"
            "3. View Logs \n\n"
            "Please enter the option : ";

        std::cin >> option;
        std::cin.ignore();
        std::cout << std::endl;
        int status;

        switch (option) {
            case 1:
                StartFirewall();
                break;

            case 2:
                status = ConfigureFirewall();
                std::cout << GetErrorMessage(status) << std::endl;
                break;

            case 3:
                ViewLogs();
                break;

            default:
                std::cout << "Error : " << GetErrorMessage(ERROR_INVALID_OPTION) << std::endl;
                exit(ERROR_INVALID_OPTION);
                break;
        }
    }
    return SUCCESS_CODE;
}

/*int StartFirewall() {
    if (!FirewallConfig::Instance().Load("firewall_rules.ini")) {
        return ERROR_INVALID_FUNCTION;
    }

    signal(SIGINT, handle_exit);
    signal(SIGTERM, handle_exit);

    std::vector<std::string> cmdlist;
    auto rulesList = FirewallConfig::Instance().GetRulesList();
    std::istringstream iss(rulesList);
    std::string line;

    while (std::getline(iss, line)) {
        if (line.empty()) continue;

        if (line[0] == '[' && line.back() == ']') {
            std::string sectionName = line.substr(1, line.length() - 2);
            auto sectionData = FirewallConfig::Instance().GetSectionData(sectionName);

            std::deque<std::string> optionList = { " -p tcp --dport ", " -j " };
            std::string command = "iptables -A ";

            int i = 0;
            for (const auto& item : sectionData) {
                auto& value = item.second;

                if (value == "in") {
                    command += "INPUT";
                    optionList.push_front(" -s ");
                } else if (value == "out") {
                    command += "OUTPUT";
                    optionList.push_front(" -d ");
                } else if (value == "any") {
                    i++;
                    continue;
                } else {
                    std::string v = (value == "permit") ? "ACCEPT" : (value == "deny") ? "DROP" : value;
                    command += optionList[i] + v;
                    i++;
                }
            }
            cmdlist.push_back(command);
        }
    }

    for (const std::string& c : cmdlist) {
        std::cout << c << std::endl << std::endl;
        system(c.c_str());
    }

    while (true) {
        std::cout << "Running" << std::endl;
        sleep(2);
    }

    return SUCCESS_CODE;
}*/
int StartFirewall() {
    if (!FirewallConfig::Instance().Load("firewall_rules.ini")) {
        std::cerr << "Failed to load firewall rules in StartFirewall\n";
        return ERROR_INVALID_FUNCTION;
    }

    std::cout << "Firewall rules loaded successfully in StartFirewall\n";

    signal(SIGINT, handle_exit);
    signal(SIGTERM, handle_exit);

    std::vector<std::string> cmdlist;
    auto rulesList = FirewallConfig::Instance().GetRulesList();
    std::istringstream iss(rulesList);
    std::string line;

    while (std::getline(iss, line)) {
        if (line.empty()) continue;

        if (line[0] == '[' && line.back() == ']') {
            std::string sectionName = line.substr(1, line.length() - 2);
            auto sectionData = FirewallConfig::Instance().GetSectionData(sectionName);

            std::deque<std::string> optionList = { " -p tcp --dport ", " -j " };
            std::string command = "iptables -A ";

            int i = 0;
            for (const auto& item : sectionData) {
                auto& value = item.second;

                if (value == "in") {
                    command += "INPUT";
                    optionList.push_front(" -s ");
                } else if (value == "out") {
                    command += "OUTPUT";
                    optionList.push_front(" -d ");
                } else if (value == "any") {
                    i++;
                    continue;
                } else {
                    std::string v = (value == "permit") ? "ACCEPT" : (value == "deny") ? "DROP" : value;
                    command += optionList[i] + v;
                    i++;
                }
            }
            cmdlist.push_back(command);
        }
    }

    for (const std::string& c : cmdlist) {
        std::cout << c << std::endl << std::endl;
        system(c.c_str());
    }

    while (true) {
        std::cout << "Running" << std::endl;
        sleep(2);
    }

    return SUCCESS_CODE;
}

int ConfigureFirewall() {
    if (!FirewallConfig::Instance().Load("firewall_rules.ini")) {
        std::cerr << "Failed to load firewall rules in ConfigureFirewall\n";
        return ERROR_INVALID_FUNCTION;
    }
    std::unordered_map<std::string, std::function<int(std::vector<std::string>&)>> command_map = {
        {"a", AddRule},
        {"add", AddRule},
        {"u", UpdateRule},
        {"update", UpdateRule},
        {"d", DeleteRule},
        {"delete", DeleteRule},
        {"l", RuleList},
        {"list", RuleList}
    };

    while (true) {
        PrintConfigMenual();
        std::cout << "COMMAND : ";
        std::string input;
        std::getline(std::cin, input);
        std::cout << std::endl;

        if (input.empty()) {
            return ERROR_INVALID_INPUT;
        }

        std::istringstream iss(input);
        std::vector<std::string> words;
        std::string word;

        while (iss >> word) {
            words.push_back(word);
        }

        for (std::string& word : words) {
            std::transform(word.begin(), word.end(), word.begin(), ::tolower);
            word = (word == "x") ? "deny" : (word == "o") ? "permit" : (word == "to") ? "out" : (word == "from") ? "in" : word;
        }

        auto cmd = command_map.find(words[0]);
        if (cmd != command_map.end()) {
            cmd->second(words);
        }
        else if (words[0] == "exit") {
            break;
        }
        else {
            return ERROR_INVALID_INPUT;
        }
    }

    return SUCCESS_CODE;
}

int AddRule(std::vector<std::string>& words) {
    std::cout << "AddRule called with: ";
    for (const auto& word : words) {
        std::cout << word << " ";
    }
    std::cout << std::endl;

    // 입력값 검증
    if (words.size() == 5 && isValidIP(words[2]) && isValidPort(words[3])) {
        std::cout << "Valid input\n";
    }
    else if (words.size() == 4) {
        if (isValidIP(words[2])) {
            words.insert(words.begin() + 3, "any");
        }
        else if (isValidPort(words[2])) {
            words.insert(words.begin() + 2, "any");
        }
        else {
            std::cout << "Invalid input\n";
            return ERROR_INVALID_INPUT;
        }
    }
    else {
        std::cout << "Invalid input\n";
        return ERROR_INVALID_INPUT;
    }

    if (!(words[1] == "out" || words[1] == "in") && (words.back() == "permit" || words.back() == "deny")) {
        std::cout << "Invalid input\n";
        return ERROR_INVALID_INPUT;
    }

    std::cout << "Attempting to add rule with: " << words[1] << " " << words[2] << " " << words[3] << " " << words[4] << std::endl;
    if (FirewallConfig::Instance().AddRule(words[1], words[2], words[3], words[4])) {
        std::cout << "Rule successfully added\n" << std::endl;
        return SUCCESS_CODE;
    }
    else {
        std::cout << "Failed to add rule\n" << std::endl;
        return ERROR_INVALID_FUNCTION;
    }
}


int UpdateRule(std::vector<std::string>& words) {
    if (words.size() != 5) {
        std::cout << "Invalid input\n";
        return ERROR_INVALID_INPUT;
    }

    std::unordered_set<std::string> validWords = {"in", "out", "permit", "deny"};
    bool isValidWord = validWords.find(words[4]) != validWords.end();

    // 입력값 검증
    if (words[3] == ">" && (isValidIP(words[4]) || isValidPort(words[4]) || isValidWord)) {
        if (FirewallConfig::Instance().UpdateRule(words[1], words[2], words[4])) {
            std::cout << "Rule successfully updated\n" << std::endl;
            return SUCCESS_CODE;
        } else {
            std::cout << "Failed to update rule\n" << std::endl;
            return ERROR_INVALID_FUNCTION;
        }
    }

    return ERROR_INVALID_INPUT;
}

int DeleteRule(std::vector<std::string>& words) {
    if (words.size() != 2) {
        std::cout << "Invalid input\n";
        return ERROR_INVALID_INPUT;
    }

    if (words[1] == "all") {
        if (FirewallConfig::Instance().DeleteRule(words[1])) {
            std::cout << "All rules successfully deleted\n" << std::endl;
            return SUCCESS_CODE;
        }
        else {
            std::cout << "Failed to delete all rules\n" << std::endl;
            return ERROR_INVALID_FUNCTION;
        }
    }
    else {
        if (FirewallConfig::Instance().DeleteRule(words[1])) {
            std::cout << "Rule successfully deleted\n" << std::endl;
            return SUCCESS_CODE;
        }
        else {
            std::cout << "Failed to delete rule\n" << std::endl;
            return ERROR_INVALID_FUNCTION;
        }
    }
}

int RuleList(std::vector<std::string>& words) {
    VariadicTable<std::string, std::string, std::string, std::string, std::string> vt({"No", "Direction", "IP Address", "PORT", "Action"}, 10);

    const auto& iniData = FirewallConfig::Instance().GetIniData(); // iniData를 가져오는 함수 호출
    for (const auto& section : iniData) {
        const auto& ruleNumber = section.first;
        const auto& ruleData = section.second;
        vt.addRow(
            ruleNumber,
            ruleData.at("direction"),
            ruleData.at("ip"),
            ruleData.at("port"),
            ruleData.at("action")
        );
    }

    vt.print(std::cout);
    return SUCCESS_CODE;
}
//getrulelist 함수 체크하기
int ViewLogs() {
    // 로그 보기 기능 구현 (필요시)
    return SUCCESS_CODE;
}

void PrintConfigMenual() {
    std::cout <<
        "\033[1;34m[ADD]    : \033[0m [A/add] [TO/FROM] [IP] [PORT] [o/x] \n"
        "\033[1;32m[UPDATE] : \033[0m [U/update] [Rule Number] [OPTION] [>] [Change Value]\n"
        "\033[1;31m[DELETE] : \033[0m [D/delete] [Rule Number] \n"
        "\033[1;33m[LIST]   : \033[0m [L/list] \n" << std::endl;
}

bool isValidIP(const std::string& ip) {
    std::regex ipPattern("^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\."
                         "(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\."
                         "(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\."
                         "(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$");
    return std::regex_match(ip, ipPattern);
}

bool isValidPort(const std::string& port) {
    std::regex portPattern("^(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}|0)$");
    return std::regex_match(port, portPattern);
}

void handle_exit(int signum) {
    std::cout << "\nProgram is terminating\n" << std::endl;
    std::string cmd = "iptables -F";
    system(cmd.c_str());
    exit(signum);
}
