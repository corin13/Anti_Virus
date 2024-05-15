#include <iostream>
#include <vector>
#include <sys/types.h>
#include <sys/stat.h>
#include <fts.h>
#include "scan.h"

using namespace std;

void scan(){
//    cout << "이 프로그램은 .. scan " << endl;

    cout << "Please enter the path : ";
    string path;
    getline(cin, path);

    cout << "\n[-] Scan Path : " << path << "\n\n";

    cout << "Select a malware scan option:\n\n"
            << "1. YARA rule\n"
            << "2. Simple file hash comparison\n\n"
            << "Please enter the option : ";
    int option;
    cin >> option;
    cin.ignore();

    cout << "\n### File Scan Start ! (Path : " << path << " , Option : " << option << ") ###\n\n";

    // 파일 순회
    scanDirectory(path, option);

    return;
}

void scanDirectory(const string& path, int option) {

    char * const paths[] = {const_cast<char *>(path.c_str()), nullptr};

    FTS *file_system = fts_open(paths, FTS_NOCHDIR | FTS_PHYSICAL, nullptr);
    if (!file_system) {
        cerr << "\nFailed to open the directory path.\n";
        return;
    }

    FTSENT *node;
    int file_count = 0;
    long long total_size = 0;
    vector<string> detectedMalware;

    while ((node = fts_read(file_system)) != nullptr) {
        if (node->fts_info == FTS_F) {
            file_count++;
            total_size += node->fts_statp->st_size;
            cout << node->fts_path << endl;
        }
        if(option == 1) {
            checkYaraRule();
        }else if(option == 2) {
            compareByHash();
        }
    }

    if (fts_close(file_system) < 0) {
        cerr << "\nFailed to close the file system.\n";
    }

    cout << "\n### End File Scan ###\n\n";

    // 스캔 결과 출력
    cout << "\n- File Scan Result -\n\n"
            << "[+] Total Malware File : " << detectedMalware.size() << " files\n";
    for (int i = 0; i < detectedMalware.size(); ++i) {
        cout << "[" << i + 1 << "] : " << detectedMalware[i] << "\n";
    }
    cout << "\n[+] Total Scan File : " << file_count << " files " << total_size << " bytes\n";
}

void compareByHash() {

}

void checkYaraRule() {

}