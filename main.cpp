#include "main.h"

void CheckOption(int &argc, char** &argv){
    int optionIndex= 0;
    int opt;
    const char* option="hidpsl"; //인자값 필요로 한다면 :붙이기 ex) hib:s:

    while((opt = getopt_long(argc, argv, option, options, &optionIndex)) != -1 ){
        switch(opt){
            case 'h':
                help(); 
                break;
            
            case 'i':
                info();
                break;

            case 'd':
                Detect();
                break;
            
            case 's':
                scan();
                break;

            case 'l':
                logging();
                break;

            case 'p':
                CollectAndSaveResourceUsage();
                break;

            case '?':
                error();
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
