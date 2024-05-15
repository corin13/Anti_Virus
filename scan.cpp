#include <iostream>
#include <vector>
#include <sys/types.h>
#include <sys/stat.h>
#include <fts.h>
#include <fstream>
#include <sstream>
#include <openssl/sha.h>
#include <iomanip>
#include "scan.h"

using namespace std;

void scan(){
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
    vector<string> hashes = loadHashes("hashes.txt");

    while ((node = fts_read(file_system)) != nullptr) {
        if (node->fts_info == FTS_F) {
            file_count++;
            total_size += node->fts_statp->st_size;
            cout << node->fts_path << endl;
        }
        if(option == 1) {
            checkYaraRule();
        }else if(option == 2) {
            compareByHash(node, detectedMalware, hashes);
        }
    }

    if (fts_close(file_system) < 0) {
        cerr << "\nFailed to close the file system.\n";
    }

    cout << "\n### End File Scan ###\n\n";

    // 스캔 결과 출력
    cout << "\n- File Scan Result -\n\n"
            << "\033[31m[+] Total Malware File : " << detectedMalware.size() << " files\033[0m\n";
    for (int i = 0; i < detectedMalware.size(); ++i) {
        cout << "\033[31m[" << i + 1 << "] : " << detectedMalware[i] << "\033[0m\n";
    }
    cout << "\n[+] Total Scan File : " << file_count << " files " << total_size << " bytes\n";
}

void compareByHash(FTSENT *node, vector<string>& detectedMalware, vector<string>& hashes) {
    string fileHash = computeSHA256(node->fts_path);
        for (const auto& hash : hashes) {
            if (fileHash == hash) {
                detectedMalware.push_back(node->fts_path);
                cout << "\n\033[31m[+] Malware detected: [" << node->fts_path << "]\033[0m\n\n";
                break;
            }
        }
}

vector<string> loadHashes(const string& filename) {
    ifstream file(filename);
    vector<string> hashes;
    string line;
    while (getline(file, line)) {
        hashes.push_back(line);
    }
    file.close();
    return hashes;
}

string computeSHA256(const string& filename) {
    ifstream file(filename, ifstream::binary);
    if (!file) {
        cerr << "Cannot open file!\n";
        return "";
    }

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    char buffer[1024];
    while (file.read(buffer, sizeof(buffer))) {
        SHA256_Update(&sha256, buffer, file.gcount());
    }
    SHA256_Update(&sha256, buffer, file.gcount());
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256);

    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }

    return ss.str();
}


void checkYaraRule() {

}