#include <iostream>
#include <fstream>
#include <sstream>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <iomanip>
#include "hash.h"

using namespace std;

void compareByHash(FTSENT *node, vector<string>& detectedMalware, vector<string>& hashes) {
    string fileHash = computeSHA256(node->fts_path); // 파일의 해시값을 계산
    for (const auto& hash : hashes) {
        if (fileHash == hash) { //계산된 해시값을 저장된 해시값들과 비교
            detectedMalware.push_back(node->fts_path);
            cout << "\n\033[31m[+] Malware detected: [" << node->fts_path << "]\033[0m\n\n";
            break;
        }
    }
}

// SHA256 해시알고리즘을 사용해서 파일의 해시값을 계산
string computeSHA256(const string& filename) {
    ifstream file(filename, ifstream::binary);
    if (!file) {
        cerr << "\n\033[31mCannot open file!\033[0m\n";
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