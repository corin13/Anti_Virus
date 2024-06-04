#define ERROR_INVALID_INPUT (200);


#include "firewall.h"

mINI::INIFile file("firewall_rules.ini");
mINI::INIStructure ini;

int Firewall() {
    int option=0;

    while (true){
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

        switch(option){
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

int StartFirewall(){
    file.read(ini);
    signal(SIGINT, handle_exit);
    signal(SIGTERM, handle_exit);

    
    std::vector<std::string> cmdlist;
    for (auto& it : ini) {
        std::deque<std::string> optionList={" -p tcp --dport ", " -j "};
        std::string command;
        command += "iptables -A ";

	    auto& collection = it.second;

        int i=0;
        int inOrOut=0;
        for (auto& it2 : collection) {
		    auto& value = it2.second;
        
            if (value == "in") {
                command+="INPUT";
                optionList.push_front(" -s ");
            }
            else if (value =="out"){
                command += "OUTPUT";
                optionList.push_front(" -d ");
            }
            else if (value =="any") {
                i++;
                continue;
            }
            else {
                std::string v =(value == "permit") ? "ACCEPT" : (value == "deny") ? "DROP" : value;
                command += optionList[i] + v;
                i++;
            }
            
        }
        cmdlist.push_back(command);
    }

    for (std::string& c : cmdlist){
        std::cout << c << std::endl << std::endl;
        system(c.c_str());
    }
    while (true){
        //tail -f 로 실시간 로그 띄우기 고민중

        std::cout << "Running" << std::endl; //테스트 용

        sleep(2);
    }

    return SUCCESS_CODE;
}



int ConfigureFirewall(){

    std::unordered_map<std::string, std::function<int(std::vector<std::string>&)>> command_map = {
        {"a", AddRule},
        {"add", AddRule},
        {"u", UpdateRule},
        {"update", UpdateRule},
        {"d", DeleteRule},
        {"delete", DeleteRule},
        {"l", RuleList},
        {"list", RuleList},
    };

    while (true){
        PrintConfigMenual();
        std::cout << "COMMAND : ";
        std::string input;
        std::getline(std::cin, input);
        std::cout << std::endl;

        
        if(input.empty()){
            return ERROR_INVALID_INPUT;
        }
        
        std::istringstream iss(input);
        std::vector<std::string> words;
        std::string word;

        

        while(iss >> word){
            words.push_back(word);
        }


        for (std::string& word : words){
            std::transform(word.begin(),word.end(),word.begin(), ::tolower);
            word=(word == "x") ? "deny" : (word == "o") ? "permit" : (word == "to") ? "out" : (word == "from") ? "in" : word;
        }

        auto cmd = command_map.find(words[0]);
        if (cmd != command_map.end()){
            cmd->second(words);
        }
        else if (words[0] == "exit"){
            break;
        }
        else{
            return ERROR_INVALID_INPUT;
        }
    }

    return SUCCESS_CODE;
}

int AddRule(std::vector<std::string>& words){
    
    //입력값 검증
    if (words.size() == 5 && isValidIP(words[2]) && isValidPort(words[3])){
        ;
    }
    else if (words.size()==4){
        if (isValidIP(words[2])) {
            words.emplace(words.begin()+3, "any");
        } 
        else if (isValidPort(words[2])){
            words.emplace(words.begin()+2, "any");
        } 
        else{
            //에러
            std::cout << "error1" << std::endl;
            exit(1);
        }
    }
    else {
        //에러
        std::cout << "error2" << std::endl;
        exit(1);
    }

    if (!((words[1] == "out" || words[1] == "in") && (words.back() == "permit" || words.back() == "deny"))){
        std::cout << "error3" << std::endl;
        exit(1);
    }
    
    //ini 파일에 데이터 추가
    file.read(ini);
    std::string ruleNum;

    if (!(ini.has("1"))){
        ruleNum="1";
    }
    else {
        auto it = std::prev(ini.end());
        std::string lastSection = it->first;
        ruleNum = std::to_string(stoi(lastSection)+1);
    }

    std::vector<std::string> keys = {"","Direction", "IP", "PORT", "Action"};

    ini[ruleNum];
    for (size_t i = 1; i < keys.size(); ++i) {
        std::string& j = words[i];
        ini[ruleNum][keys[i]] = j;
    }
    file.write(ini);

    std::cout << "Rule successfully added \n" << std::endl;
    return SUCCESS_CODE;
    
}

// 기존 룰 업데이트 함수
int UpdateRule(std::vector<std::string>& words){
    if (words.size() == 5){
        file.read(ini);
        std::unordered_set<std::string> validWords = {"in", "out", "permit", "deny"};
        bool isValidWord = validWords.find(words[4]) != validWords.end();

        //입력값 검증
        if (ini[words[1]].has(words[2]) && words[3] == ">"){
            if (isValidIP(words[4]) || isValidPort(words[4]) || isValidWord){
                ini[words[1]][words[2]]=words[4];
                file.write(ini);

                std::cout << "Rule successfully Updated\n" << std::endl;
                return SUCCESS_CODE;
            }
            
        }
    }

    return ERROR_INVALID_INPUT;

}


// 방화벽 룰 삭제 함수
int DeleteRule(std::vector<std::string>& words){
    //중간 번호 룰이 삭제될 시 뒷 번호들 -1씩 되는 기능 필요
    file.read(ini);
    if (words[1] == "all"){
        ini.clear();
    }
    else if (ini.has(words[1])){
        ini.remove(words[1]);
    }
    else{
        return ERROR_INVALID_INPUT;
    }

    file.write(ini);
    std::cout << "Rule successfully Deleted\n" << std::endl;
    return SUCCESS_CODE;
}


// 현재 설정된 방화벽 룰 확인 함수
int RuleList(std::vector<std::string>& words){
    VariadicTable<std::string, std::string, std::string, std::string, std::string> vt({"No", "Direction", "IP Address", "PORT", "Action"}, 10);
    
    file.read(ini);

    for (auto const& it : ini){ 
        std::vector<std::string> tmp;
        auto const& section = it.first;
        auto const& collection = it.second;
        
         for (auto const& it2 : collection){
            tmp.push_back(it2.second);
	    }
        vt.addRow(section,tmp[0],tmp[1],tmp[2],tmp[3]);
    }

    vt.print(std::cout);

    return SUCCESS_CODE;
}

int ViewLogs(){
    return SUCCESS_CODE;
}


////////////////////////////////////////////////////////////////////////////////////////
//private

// IP의 형식이 맞는지 비교하는 함수
bool isValidIP(const std::string& ip) {
    std::regex ipPattern("^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\."
                         "(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\."
                         "(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\."
                         "(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$");
    return std::regex_match(ip, ipPattern);
}

// port의 형식이 맞는지 비교하는 함수
bool isValidPort(const std::string& port) {
    std::regex portPattern("^(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}|0)$");
    return std::regex_match(port, portPattern);
}



// 2번 기능 메뉴얼 출력 함수
void PrintConfigMenual(){
    std::cout << 
        "\033[1;34m[ADD]    : \033[0m [A/add] [TO/FROM] [IP] [PORT] [o/x] \n"
        "\033[1;32m[UPDATE] : \033[0m [U/update] [Rule Number] [OPTION] [>] [Change Value]\n"
        "\033[1;31m[DELETE] : \033[0m [D/delete] [Rule Number] \n"
        "\033[1;33m[LIST]   : \033[0m [L/list] \n" << std::endl;
}

// 프로그램 종료 시 iptables 룰 초기화 함수
void handle_exit(int signum) {
    std::cout << "\n program is terminating\n" << std::endl;
    std::string cmd;

    cmd = "iptables -F";
    system(cmd.c_str());

    exit(signum);
}