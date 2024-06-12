#include "firewall.h"


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
                RunFirewall();
                break;

            case 2:
                status = ConfigureFirewall();
                std::cout << GetErrorMessage(status) << std::endl;
                break;

            case 3:
                ViewLogs();
                break;

            default:
                std::cerr << "Error : " << GetErrorMessage(ERROR_INVALID_OPTION) << std::endl;
                exit(ERROR_INVALID_OPTION);
                break;
        }
    }
    return SUCCESS_CODE;
}


int RunFirewall(){
    if (!FirewallConfig::Instance().Load("firewall_rules.ini")) {
        std::cerr << "Failed to load firewall rules in StartFirewall\n";
        return ERROR_INVALID_FUNCTION;
    }

    
    signal(SIGINT, handle_exit);
    signal(SIGTERM, handle_exit);
    

    auto& iniData = FirewallConfig::Instance().GetIniData();
    for (auto id : iniData){
        std::vector<std::string> iniList;

        for (auto idSecond : id.second){
            iniList.push_back(idSecond.second);
        }
        RunIptables(iniList[DIRECTION], iniList[IP], iniList[PORT],iniList[ACTION]);
    }

    while (true){
        std::cout << "run" << std::endl;
        sleep(1);
    }

    return SUCCESS_CODE;
    // ExecCommand("iptables -A INPUT -j LOG --log-prefix \"INPUT packet: \" --log-level 1");
    // ExecCommand("iptables -A OUTPUT -j LOG --log-prefix \"OUTPUT packet: \" --log-level 1");
    
}



int ConfigureFirewall(){
    if (!FirewallConfig::Instance().Load("firewall_rules.ini")) {
        std::cerr << "Failed to load firewall rules in ConfigureFirewall\n";
        return ERROR_INVALID_FUNCTION;
    }

    int statusCode = SUCCESS_CODE;

    while (true){
    
        std::string input;
        std::vector<std::string> words;

        PrintConfigMenual();

        std::getline(std::cin, input);
        std::cout << std::endl;

        if(input.empty()){
            std::cerr << "Input cannot be only spaces." << std::endl;
            return ERROR_INVALID_INPUT;
        }
        
        words = ConfigureUserInput(input);

        if (isVaildInput(words) != SUCCESS_CODE){
            continue;
        }

        std::string cmd = words[COMMAND];
        

        if (cmd =="a"){
            statusCode=AddRule(words);
        }
        else if (cmd == "u"){
            statusCode=UpdateRule(words);
        }
        else if (cmd == "d") {
            statusCode = DeleteRule(words);
        }
        else if (cmd == "l"){
            statusCode = RuleList();
        }
        else if (cmd == "help"){
            statusCode = FirewallHelp();
        }

        else if (cmd == "exit"){
            statusCode = EXIT_CONFIG;
            break;
        }

        if (statusCode !=SUCCESS_CODE){
            break;
        }
    }

    return statusCode;
}



int RunIptables(std::string direction, std::string ip, std::string port, std::string action){
    std::string iptablesCmd="iptables -A";

    if (direction == "INPUT"){
        iptablesCmd += " INPUT ";
        iptablesCmd += ip == "ANY" ? "" : "-s "+ip;
    }
    else if (direction == "OUTPUT"){
        iptablesCmd += " OUTPUT ";
        iptablesCmd += ip == "ANY" ? "" : "-d "+ip;
    }
    else {
        std::cerr << "Invalid Direction" << std::endl;
        return ERROR_INVALID_OPTION;
    }

    iptablesCmd += port == "ANY" ? "" : " -p tcp --dport "+port;

    if (action =="DROP"){
        iptablesCmd += " -j DROP";
    }
    else if (action == "ACCEPT"){
        iptablesCmd += " -j ACCEPT";
    }
    else {
        std::cerr << "Invalid Action" << std::endl;
        return ERROR_INVALID_OPTION;
    }


    std::cout << iptablesCmd << std::endl;

    FILE* pipe = popen(iptablesCmd.c_str(), "r");
    if (!pipe) {
        std::cerr << "ERROR : popen() failed" << std::endl;
        return ERROR_UNKNOWN;
    }
    
    char buffer[128];

    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        std::cout << buffer;
    }

    pclose(pipe);

    return SUCCESS_CODE;
}

void ExecCommand(std::string cmd){
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        std::cerr << "ERROR : popen() failed" << std::endl;
        return;
    }
    
    char buffer[128];

    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        std::cout << buffer;
    }

    pclose(pipe);
}


std::vector<std::string> ConfigureUserInput(std::string& input){
    std::istringstream iss(input);
    std::vector<std::string> words;
    std::string word;

    while(iss >> word){
        //소문자로 변경
        std::transform(word.begin(),word.end(),word.begin(),::tolower); 

        //iptables 형식에 맞게 변환
        word = (word == "add") ? "a" : (word == "update") ? "u" : (word == "delete") ? "d" : (word == "list") ? "l" : word;
        word = (word == "x" || word == "drop") ? "DROP" : (word == "o" || word=="accept") ? "ACCEPT" :  word;
        word = (word == "to" || word =="output") ? "OUTPUT" : (word == "from" || word == "input") ? "INPUT" : word;
        word = (word == "any") ? "ANY" : word;

        words.push_back(word);
    }
    
    if (words[COMMAND] =="a"){
        if (words.size() == ADD_MIN_LENGHT){
            if (isValidIP(words[ADD_IP])){
                words.emplace(words.begin()+ADD_PORT, "ANY");
            }
            else if (isValidPort(words[ADD_IP])){
                words.emplace(words.begin()+ADD_IP, "ANY");
            }
        }
    }

    return words;
}



int isVaildInput(std::vector<std::string>& words) {
    if (!FirewallConfig::Instance().Load("firewall_rules.ini")) {
        std::cerr << "Failed to load firewall rules in ConfigureFirewall\n";
        return ERROR_INVALID_FUNCTION;
    }
    auto& iniData = FirewallConfig::Instance().GetIniData();

    std::vector<std::string> directionWords = {"INPUT", "OUTPUT"};
    std::vector<std::string> actionWords = {"DROP", "ACCEPT"};
    
    std::string command= words[COMMAND];

    if (command =="a"){
        
        //길이 검증
        if (!(words.size() == ADD_MIN_LENGHT || words.size() == ADD_MAX_LENGTH)){
            std::cerr << "Invalid length input." << std::endl;
            return ERROR_INVALID_INPUT;
        }

        //입력값 검증
        if (std::find(directionWords.begin(),directionWords.end(),words[ADD_DIRECTION]) == directionWords.end()){
            PrintInputError(words[ADD_DIRECTION]);
            return ERROR_INVALID_INPUT;
        }
        if (!isValidIP(words[ADD_IP])){
            PrintInputError(words[ADD_IP]);
            return ERROR_INVALID_INPUT;
        }
        if (!isValidPort(words[ADD_PORT])){
            PrintInputError(words[ADD_PORT]);
            return ERROR_INVALID_INPUT;
        }
        if (std::find(actionWords.begin(),actionWords.end(),words[ADD_ACTION]) == actionWords.end()){
            PrintInputError(words[ADD_ACTION]);
            return ERROR_INVALID_INPUT;
        }

        return SUCCESS_CODE;
    }
    else if (command == "u"){
        
        //길이 검증
        if (words.size() != UPDATE_LENGTH){
            std::cerr << "Invalid length input." << std::endl;
            return ERROR_INVALID_INPUT;
        }

        //입력값 검증

        if (!isValidNumber(words[UPDATE_NUMBER])) {
            PrintInputError(words[UPDATE_NUMBER]);
            return ERROR_INVALID_INPUT;
        }

        int UpdateNum = std::stoi(words[UPDATE_NUMBER]);

        if (iniData.size() < UpdateNum || UpdateNum < 1) {
            PrintInputError(words[UPDATE_NUMBER]);
            return ERROR_INVALID_INPUT;
        }

        if (words[UPDATE_REDIRECTION] != ">"){
            PrintInputError(words[UPDATE_REDIRECTION]);
            return ERROR_INVALID_INPUT;
        }

        if (words[UPDATE_OPTION] =="direction"){
            if (std::find(directionWords.begin(),directionWords.end(),words[UPDATE_NEW_VALUE]) == directionWords.end()){
                PrintInputError(words[UPDATE_NEW_VALUE]);
                return ERROR_INVALID_INPUT;
            }
        }
        else if (words[UPDATE_OPTION] == "ip"){
            if (!isValidIP(words[UPDATE_NEW_VALUE])){
                PrintInputError(words[UPDATE_NEW_VALUE]);
                return ERROR_INVALID_INPUT;
            }
        }
        else if (words[UPDATE_OPTION] == "port") {
            if (!isValidPort(words[UPDATE_NEW_VALUE])){
                PrintInputError(words[UPDATE_NEW_VALUE]);
                return ERROR_INVALID_INPUT;
            }
        }
        else if (words[UPDATE_OPTION] == "action") {
            if (std::find(actionWords.begin(),actionWords.end(),words[UPDATE_NEW_VALUE]) == actionWords.end()){
                PrintInputError(words[UPDATE_NEW_VALUE]);
                return ERROR_INVALID_INPUT;
            }
        }
        else {
            PrintInputError(words[UPDATE_NEW_VALUE]);
            return ERROR_INVALID_INPUT;
        }

        return SUCCESS_CODE;
        
    }
    else if (command == "d"){
        //길이 검증
        if (words.size() != DELETE_LENGTH) {
            std::cerr << "Invalid length input." << std::endl;
            return ERROR_INVALID_INPUT;
        }

        //입력값 검증

        if (words[DELETE_NUMBER] == "all"){
            return SUCCESS_CODE;
        }

        if (!isValidNumber(words[DELETE_NUMBER])){
            PrintInputError(words[DELETE_NUMBER]);
            return ERROR_INVALID_INPUT;
        }

        int delNum = std::stoi(words[DELETE_NUMBER]);

        if (iniData.size() < delNum || delNum < 1){
            PrintInputError(words[DELETE_NUMBER]);
            return ERROR_INVALID_INPUT;
        }

        return SUCCESS_CODE;

    }     
    else if (command == "l"){
        if (words.size() !=1) {
            std::cerr << "Invalid Input" << std::endl;
            return ERROR_INVALID_INPUT;
        }
        return SUCCESS_CODE;
    }
    else if (command == "exit" || command == "help"){
        return SUCCESS_CODE;
    }
    else {
        PrintInputError(command);
        return ERROR_INVALID_INPUT; 
    }

    return ERROR_UNKNOWN;
}

int AddRule(std::vector<std::string>& words){
    try{
        FirewallConfig::Instance().AddRule(
            words[ADD_DIRECTION], 
            words[ADD_IP], 
            words[ADD_PORT], 
            words[ADD_ACTION]
        );
        
    std::cout << "Rule successfully added\n" << std::endl;
    return SUCCESS_CODE;    
    }
    catch(std::exception &e) {
        std::cerr << "ERROR : " << e.what() << std::endl;
        return ERROR_UNKNOWN;
    }
}




// 기존 룰 업데이트 함수
int UpdateRule(std::vector<std::string>& words){
    
    if (!FirewallConfig::Instance().Load("firewall_rules.ini")) {
        std::cerr << "Failed to load firewall rules in ConfigureFirewall\n";
        return ERROR_INVALID_FUNCTION;
    }

    try {
        auto& iniData = FirewallConfig::Instance().GetIniData();
        std::string sectionName;

        sectionName = GetSectionName(iniData, std::stoi(words[UPDATE_NUMBER]));
        FirewallConfig::Instance().UpdateRule(sectionName, words[UPDATE_OPTION], words[UPDATE_NEW_VALUE]);
        
        std::cout << "Rule successfully Updated\n" << std::endl;

        return SUCCESS_CODE;
    }
    catch(std::exception &e) {
        std::cerr << "ERROR : " << e.what() << std::endl;
        return ERROR_UNKNOWN;
    }
}


//룰 삭제 함수
int DeleteRule(std::vector<std::string>& words){
    if (!FirewallConfig::Instance().Load("firewall_rules.ini")) {
        std::cerr << "Failed to load firewall rules in ConfigureFirewall\n";
        return ERROR_INVALID_FUNCTION;
    }

    auto iniData = FirewallConfig::Instance().GetIniData();

    std::string sectionName;

    if (words[DELETE_NUMBER] == "all") {
        sectionName = "all";
    }
    else {
        sectionName = GetSectionName(iniData, std::stoi(words[DELETE_NUMBER]));
    }

    FirewallConfig::Instance().DeleteRule(sectionName);



    std::cout << "Rule successfully Deleted\n" << std::endl;
    return SUCCESS_CODE;
}


// 현재 설정된 방화벽 룰 확인 함수
int RuleList(){
    if (!FirewallConfig::Instance().Load("firewall_rules.ini")) {
        std::cerr << "Failed to load firewall rules in ConfigureFirewall\n";
        return ERROR_INVALID_FUNCTION;
    }
    VariadicTable<int, std::string, std::string, std::string, std::string> vt({"No", "Direction", "IP Address", "PORT", "Action"}, 10);
    
    auto iniData = FirewallConfig::Instance().GetIniData();
    int ruleNumber =0;

    for (auto& id : iniData){
        ruleNumber++;
        std::vector<std::string> dataFormat;

        for (auto& sd : id.second){
            dataFormat.push_back(sd.second);
        }
        vt.addRow(ruleNumber,dataFormat[DIRECTION],dataFormat[IP],dataFormat[PORT],dataFormat[ACTION]);
    }

    vt.print(std::cout);

    return SUCCESS_CODE;
}

int ViewLogs(){
    return SUCCESS_CODE;
}




std::string GetSectionName(auto& iniData, int number){
    int cnt =1;
    for (auto& id : iniData){
        if (number == cnt){
            return id.first;
        }
        else {
            cnt ++;
        }
    }

    return "";
}


// IP의 형식이 맞는지 비교하는 함수
bool isValidIP(const std::string& ip) {
    std::regex ipPattern("^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\."
                         "(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\."
                         "(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\."
                         "(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$");
    
    return std::regex_match(ip, ipPattern) || ip == "ANY";
}

bool isValidPort(const std::string& port) {
    std::regex portPattern("^(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}|0)$");
    return std::regex_match(port, portPattern) || port == "ANY";
}

bool isValidNumber(const std::string& number){
    std::istringstream iss(number);
    int num;

    return (iss >> num) && (iss.eof());
}


// 2번 기능 메뉴얼 출력 함수
void PrintConfigMenual(){
    std::cout << 
        "\033[1;34m[ADD]    : \033[0m [A/add] [TO/FROM] [IP] [PORT] [ACCEPT(o)/DROP(x)] \n"
        "\033[1;32m[UPDATE] : \033[0m [U/update] [Rule Number] [OPTION] [>] [Change Value]\n"
        "\033[1;31m[DELETE] : \033[0m [D/delete] [Rule Number] \n"
        "\033[1;33m[LIST]   : \033[0m [L/list] \n\n" 

        "\033[36m[EXIT]\033[0m "
        "\033[35m[HELP]\033[0m \n\n"

        "COMMAND : ";
}

void PrintInputError(std::string error){
    std::cerr << "Invalid Input : \"" << error << "\"" << std::endl;
}

// 프로그램 종료 시 iptables 룰 초기화 함수
void handle_exit(int signum) {
    std::cout << "\nProgram is terminating\n" << std::endl;
    std::string cmd = "iptables -F";
    system(cmd.c_str());
    exit(signum);
}

int FirewallHelp() {
    std::cout << 
        "A, add     -Rule Add Command\n"       
        "-[TO]    : Outbound network\n"
        "-[FROM]  : Inbound network\n"
        "-[DROP]  : Blocking the network\n"
        "-[ACCEPT]: Allow the network\n\n"

        "U, update  -Rule Update Command \n"
        "-[Rule Number] : Rule Index Number\n"
        "-[OPTION]: The title of the value you want to change\n"
        "-[>]     : Must use '>' \n"
        "-[Change Value]: Value to change\n\n"

        "D, delete  -Rule Delete Command \n"    
        "-[Rule Number] : Rule Index Number\n\n"

        "L, list    -Rule Inquiry Command\n\n"
        
        "EXIT       -End Rule Set Commands\n" 
        << std::endl;  
    return SUCCESS_CODE;
}
