#include "main.h"

CUdkdAgentOptions IAgentOptions;
CUsageCollector IUsageOption;

void CheckOption(int &argc, char** &argv){
    int optionIndex= 0;
    int opt;
    const char* option="hidusl"; //인자값 필요로 한다면 :붙이기 ex) hib:s:

    while((opt = getopt_long(argc, argv, option, options, &optionIndex)) != -1 ){
        switch(opt){
            case 'h':
                IAgentOptions.DisplayHelpOption(); 
                break;
            
            case 'i':
                IAgentOptions.DisplayInfoOption();
                break;

            case 'd':
                Detect();
                break;
            
            case 's':
                StartScan();
                break;

            case 'l':
                logging();
                break;

            case 'u':
                IUsageOption.CollectAndSaveUsage();
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

    //옵션 값 확인
    if (argc > 1) 
        CheckOption(argc, argv);
    else
        std::cout << "Try 'UdkdAgent --help' for more information." << std::endl;

    return 0;
}
