#include <iostream>
#include <getopt.h>
#include "main.h"

using namespace std;

void CheckOpt(int argc, char** argv){
    int optionIndex= 0;
    int opt;
    const char* option="hibs"; //인자값 필요로 한다면 :붙이기 ex) hib:s:

    while((opt = getopt_long(argc, argv, option, options, &optionIndex)) != -1 ){
        switch(opt){
            case 'h':
                cout << "HELP" << endl; //기능 함수 넣기
                break;

            case 'i':
                info();
                break;

            case 'b':
                cout << "BACKGROUND" << endl;
                break;
            
            case 's':
                cout << "SCAN" << endl;
                break;

            case '?':
                cout << "Error" << endl;
                break;

            default:
                abort();
        }
    }

}

int main(int argc, char **argv){
    
    //옵션 값 확인
    if (argc > 1) 
        CheckOpt(argc, argv);
    else
        cout << "Try 'UdkdAgent --help' for more information." << endl;


    return 0;
}