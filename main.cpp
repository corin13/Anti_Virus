#include "main.h"

CUdkdAgentOptions IAgentOptions;
CUsageCollector IUsageOption;
CLoggingManager ILoggingOption;

// 인자값 필요로 한다면 :붙이기 ex) hib:s:
void CheckOption(int &argc, char** &argv){
    int nOptionIndex= 0;
    int nOpt;
    const char* pOption="c:dhilmsu"; 
    std::string configPath;

    while((nOpt = getopt_long(argc, argv, pOption, options, &nOptionIndex)) != -1 ){
        switch(nOpt){
            case 'd':
                Detect();
                break;

            case 'h':
                IAgentOptions.DisplayHelpOption(); 
                break;
            
            case 'i':
                IAgentOptions.DisplayInfoOption();
                break;
            
            case 'l':
                ILoggingOption.TestLogging();
                break;

            case 'm':
                if (configPath.empty()) {
                    configPath = "./config.ini"; // 기본 설정 파일 경로
                }
                LoadConfig(configPath);
                StartMonitoring();
                break;

            case 's':
                StartScan();
                break;

            case 'u':
                IUsageOption.CollectAndSaveUsage();
                break;


            case 'c':
                LoadConfig(optarg);
                StartIniScan(); 
                break;

            case '?':
                IAgentOptions.DisplayErrorOption();
                break;
            
            
            default:
                abort();
        }
    }
}

int main(int argc, char **argv){
    if (argc > 1) 
        CheckOption(argc, argv);
    else
        std::cout << "Try 'UdkdAgent --help' for more information." << std::endl;
    return 0;
}

void LoadConfig(const std::string& configPath) {
    if (Config::Instance().Load(configPath)) {
        std::cout << "Configuration loaded successfully from " << configPath << ".\n";
    } else {
        std::cerr << "Failed to load configuration from " << configPath << ".\n";
    }
}