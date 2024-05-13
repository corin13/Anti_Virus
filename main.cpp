#include <iostream>
#include <getopt.h>


using namespace std;

struct option options[]={
    {"help", no_argument, 0, 'h'},
    {"info", no_argument, 0, 'i'},
    {"background",no_argument, 0, 'b'},
    {"scan", no_argument, 0,'s'}, //인자값 필요로 한다면 no_argument -> required_argument
    {0,0,0,0}
};

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
                cout << "INFO" << endl;
                break;

            case 'b':
                cout << "BACKGROUND" << endl;

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