#include "main.h"

CUdkdAgentOptions IAgentOptions;
CUsageCollector IUsageOption;
CLoggingManager ILoggingOption;

// 인자값 필요로 한다면 :붙이기 ex) hib:s:
void CheckOption(int &argc, char** &argv){
    int nOptionIndex= 0;
    int nOpt;
    const char* pOption="dhilmsuf";

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
                StartMonitoring();
                break;

            case 's':
                StartScan();
                break;

            case 'u':
                IUsageOption.CollectAndSaveUsage();
                break;

            case 'f':
                Firewall();
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
