#include "antidbg.h"

using namespace std;

int logic1(){
    DIR* dir;
    struct dirent *entry;
    vector<string> dbgs={"ida", "gdb"};
    
    dir = opendir("/proc");

    while((entry = readdir(dir)) != nullptr){
        string path = "/proc/" + string(entry->d_name);
        
        if (entry->d_type == DT_DIR && string(entry->d_name).find_first_not_of("0123456789") == string::npos){
            string comm_path = path+"/comm";
            ifstream comm_file(comm_path);
            string process_name;

            if (comm_file >> process_name){
                if (find(dbgs.begin(), dbgs.end(), process_name) != dbgs.end()){
                    kill(stoi(entry->d_name), SIGKILL);
                    cout << "Debugger detected! Terminating program" << endl;
                }
            }
            comm_file.close();
        }
    }
    closedir(dir);
    cout << "No Debugger detected! " << endl;

    return 0;
}

void detect(){
    logic1();
    
    // if(strcmp(argv, "proc")==0){
    //     logic1();
    // }
    // else if(strcmp(argv, "self") == 0){

    // }
}