#include <iostream>
#include <unistd.h>

using namespace std;

// void CheckOpt(int option){

// }


int main(int argc, char* argv[]){
    if (argc > 1) 
        for (int i=0; i < argc; i++)
            cout << argv[i] << endl;

    else
        cout << "Try 'UdkdAgent --help' for more information." << endl;

    int option;

    while((option = getopt(argc, argv, "bfs:") != -1)){
    }


    return 0;
}