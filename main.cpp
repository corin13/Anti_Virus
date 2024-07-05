#include "main.h"
#include "config.h"
#include "crypto_utils.h"

CUdkdAgentOptions IAgentOptions;
CUsageCollector IUsageOption;
CLoggingManager ILoggingOption;
CPacketHandler INetworkingOption;
CEventMonitor IEventMonitor;
CFileScanner IFileScanner;
CNetworkInterface IUserProgram;
CAntiDebugger IAntiDebugger;
CFirewall IFirewall;

// 인자값 필요로 한다면 :붙이기 ex) hib:s:
void CheckOption(int &argc, char** &argv) {
    int nOptionIndex = 0;
    int nOpt;
    const char* pOption = "c:dhilmsunfe"; 
    bool bNetworkOption = false;
    std::string configPath;

    while ((nOpt = getopt_long(argc, argv, pOption, options, &nOptionIndex)) != -1) {
        switch (nOpt) {
            case 'd':
                IAntiDebugger.Detect();
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
                    configPath = CONFIGPATH;
                }
                std::cout << "Configuration path for -m: " << configPath << std::endl;
                LoadConfig(configPath);
                IEventMonitor.StartMonitoring();
                break;
            case 's':
                IFileScanner.StartScan();
                break;
            case 'u':
                IUsageOption.CollectAndSaveUsage();
                break;
            case 'n':
                IUserProgram.ManageInterface();
                bNetworkOption = true;
                break;
            case 'c':
                LoadConfig(optarg);
                IFileScanner.StartIniScan();
                break;
            case 'f':
                IFirewall.StartFirewall();
                break;
            case 'e': {
                std::string configPath = CONFIGPATH;
                LoadConfig(configPath);
                std::string recipientEmailAddress = Config::Instance().GetEmailAddress(); // 이메일 주소 가져오기
                std::cout << "Recipient Email Address: " << recipientEmailAddress << std::endl; // 이메일 주소 출력 (디버그용)
                EmailSender IEmailSender("smtps://smtp.gmail.com", 465, recipientEmailAddress); // EmailSender 객체 초기화 
                IEmailSender.SendLogEmail(); // 이메일 보내기 함수 호출
                break;
            }
            case '?':
                IAgentOptions.DisplayErrorOption();
                break;
            default:
                abort();
        }
    }
}

int main(int argc, char **argv){
    const std::string keyFilePath = ENCRYPTION_KEY;

    if (!CCryptoUtils::FileExists(keyFilePath)) {
        std::vector<unsigned char> key = CCryptoUtils::GenerateRandomKey(32);
        CCryptoUtils::SaveKeyToFile(key, keyFilePath);
    }
    if (argc > 1)
        CheckOption(argc, argv);
    else
        std::cout << "Try 'UdkdAgent --help' for more information." << std::endl;
    return 0;
}

void LoadConfig(const std::string& configPath) {
    try {
        Config::Instance().Load(configPath);
        std::cout << "Configuration loaded successfully from " << configPath << ".\n";
        std::cout << "----------------------------------------\n";
    } catch (const std::exception &e) {
        std::cerr << "Failed to load configuration from " << configPath << ": " << e.what() << "\n";
        exit(ERROR_CANNOT_OPEN_FILE);
    }
}