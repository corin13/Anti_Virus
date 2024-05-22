#define DETECT (10)

#include "antidbg.h"


std::string GetStatInfo(const std::string& path) {
    std::string stat_path = path + "/stat";
    std::ifstream stat_file(stat_path);
    std::string stat;

    if (!stat_file.is_open()) {
        throw std::runtime_error("Failed to open file: " + stat_path);
    }

    std::getline(stat_file, stat);
    stat_file.close();
    return stat;
}

std::vector<std::string> ParseStat(const std::string& stat) {
    std::istringstream iss(stat);
    std::string token;
    std::vector<std::string> tokens;

    while (iss >> token) {
        tokens.push_back(token);
    }
    return tokens;
}

int CheckProcess() {
    DIR* dir;
    struct dirent* entry;
    std::vector<std::string> dbg_pids;
    std::vector<std::string> udkd_pids;
    std::vector<std::string> udkd_ppids;
    std::vector<std::string> stat_parse;

    //dir open
    if ((dir = opendir("/proc")) == nullptr){
        return 2;
    }

    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type == DT_DIR && std::string(entry->d_name).find_first_not_of("0123456789") == std::string::npos) {
            std::string path = "/proc/" + std::string(entry->d_name);
            std::string stat;

            try {
                stat = GetStatInfo(path);
            } catch (const std::exception& e) {
                std::cerr << e.what() << std::endl;
                return 4;
            }

            std::vector<std::string> stat_parse = ParseStat(stat);

            if (stat_parse[1] == "(gdb)") {
                dbg_pids.push_back(stat_parse[0]);
            } else if (stat_parse[1] == "(UdkdAgent)") {
                udkd_pids.push_back(stat_parse[0]);
                udkd_ppids.push_back(stat_parse[3]);
            }
        }
    }
    closedir(dir);

    // Kill process
    for (size_t i = 0; i < udkd_pids.size(); ++i) {
        if (std::find(dbg_pids.begin(), dbg_pids.end(), udkd_ppids[i]) != dbg_pids.end()) {
            kill(std::stoi(udkd_pids[i]), SIGTERM);
            return 11;
        }

    }
    return 0;
}

void Detect() {
    std::cout << "Process started. The system is now protected against debugging attempts." << std::endl;

    while (true) {
        switch (CheckProcess()) {
            case 0:
                std::cout << "Anti-debugging Logic Running…" << std::endl;
                break;
            case 1:
                std::cout << "Error : Invalid Function" << std::endl;
                exit(1);
                break;
            case 2:
                std::cout << "Error : Not Found File/directory" << std::endl;
                exit(2);
                break;
            case 4:
                std::cout << "Error : Failed Open File" << std::endl;
                break;
                
            case 11:
                std::cout << "Debugger detected! Terminating program" << std::endl;
                break;

            default:
                std::cout << "Error : Program Error" << std::endl;
                exit(1);
                break;
        }

        sleep(3);
    }
}