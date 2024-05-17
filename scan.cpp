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
#include <yara.h>

using namespace std;


//-s 혹은 --scan 옵션 입력 시 scan() 함수 실행됨
void scan(){
    cout << "Please enter the path (Default is '/') : ";
    string path;
    getline(cin, path);

    if(path.empty()) {
        path = "/"; // 경로가 비어있을 경우 디폴트로 '/' 설정
    }
    if (!isDirectory(path)) { // 경로 유효성 검사
        printError("Invalid path. Please enter a valid directory path.");
        return;
    }

    cout << "\n[-] Scan Path : " << path << "\n\n";

    cout << "Select a malware scan option:\n\n"
            << "1. YARA rule\n"
            << "2. Simple file hash comparison\n\n"
            << "Please enter the option : ";
    int option;
    cin >> option;
    cin.ignore();

    if (option != 1 && option != 2) {
        printError("Invalid option selected. Please enter 1 or 2.");
        return; // 잘못된 입력일 경우 함수 종료
    }

    cout << "\n### File Scan Start ! (Path : " << path << " , Option : " << option << ") ###\n\n";

    // 사용자가 지정한 디렉토리 내의 모든 파일을 순회하면서 악석파일 검사
    scanDirectory(path, option);

    return;
}

// 경로 유효성 검사 함수
bool isDirectory(const string& path) {
    struct stat info;
    if (stat(path.c_str(), &info) != 0) {
        return false;
    }
    return (info.st_mode & S_IFDIR) != 0;
}

void scanDirectory(const string& path, int option) {

    char * const paths[] = {const_cast<char *>(path.c_str()), nullptr};

    FTS *file_system = fts_open(paths, FTS_NOCHDIR | FTS_PHYSICAL, nullptr);
    if (file_system == NULL) {
        printError("Failed to open the directory path.");
        return;
    }

    FTSENT *node;
    int file_count = 0;
    long long total_size = 0;
    vector<string> detectedMalware; // 악성파일로 판별된 파일의 경로를 저장
    vector<string> hashes = loadHashes("hashes.txt"); // hashes.txt는 악성파일 해시값이 저장되어있는 텍스트 파일(현재는 테스트용으로 test.txt의 해시값이 저장되어 있음)

    // 파일을 한개씩 순회해서 사용자가 입력한 옵션에 따라 검사
    if(option == 1) {
        while ((node = fts_read(file_system)) != nullptr) {
            if (node->fts_info == FTS_F) {
                file_count++;
                total_size += node->fts_statp->st_size;
                cout << node->fts_path << "\n";
                checkYaraRule(node->fts_path, detectedMalware);
            }
        }    
    }
    else if(option == 2) {
        while ((node = fts_read(file_system)) != nullptr) {
            if (node->fts_info == FTS_F) {
                file_count++;
                total_size += node->fts_statp->st_size;
                cout << node->fts_path << "\n";
                compareByHash(node, detectedMalware, hashes);
            }
        }
    }

    if (fts_close(file_system) < 0) {
        printError("Failed to close the file system.");
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
    string fileHash = computeSHA256(node->fts_path); // 파일의 해시값을 계산
    for (const auto& hash : hashes) {
        if (fileHash == hash) { //계산된 해시값을 저장된 해시값들과 비교
            detectedMalware.push_back(node->fts_path);
            cout << "\n\033[31m[+] Malware detected: [" << node->fts_path << "]\033[0m\n\n";
            break;
        }
    }
}

// hashes.txt의 내용을 vector로 변환
vector<string> loadHashes(const string& filename) {
    ifstream file(filename);
    if (!file.is_open()) {
        printError("Failed to open hash file: " + filename);
        return {};
    }
    vector<string> hashes;
    string line;
    while (getline(file, line)) {
        hashes.push_back(line);
    }
    file.close();
    return hashes;
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

void printError(const string& message) {
    cerr << "\n\033[31m" << message << "\033[0m\n";
}

// YARA 룰 매칭 콜백 함수
int yaraCallbackFunction(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        auto* data = static_cast<UserData*>(user_data);        
        vector<string>* detectedMalware = data->detectedMalware;
        const string* file_path = data->filePath; // 파일 경로 가져오기
        detectedMalware->push_back(*file_path);
        cout << "\n\033[31m[+] Malware detected: [" << *file_path << "]\033[0m\n\n";
    }
    return CALLBACK_CONTINUE;
}



void checkYaraRule(const string& filePath, vector<string>& detectedMalware) {
    YR_COMPILER* compiler = nullptr;
    YR_RULES* rules = nullptr;

    // yara 라이브러리 초기화
    if (yr_initialize() != ERROR_SUCCESS) {
        cerr << "Failed to initialize YARA." << endl;
        return;
    }
    // yara 컴파일러 객체 생성
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        cerr << "Failed to create YARA compiler." << endl;
        yr_finalize();
        return;
    }
    // yara rule 파일 열기
    const char* ruleFile = "rules.yara";
    FILE* ruleFilePtr = fopen(ruleFile, "r");
    if (!ruleFilePtr) {
        cout << "Failed to open YARA rules file." << endl;
        yr_compiler_destroy(compiler);
        yr_finalize();
        return;
    }
    // yara rule 컴파일
    if (yr_compiler_add_file(compiler, ruleFilePtr, nullptr, ruleFile) != 0) {
        cout << "Failed to compile YARA rules." << endl;
        fclose(ruleFilePtr);
        yr_compiler_destroy(compiler);
        yr_finalize();
        return;
    }
    fclose(ruleFilePtr);

    
    if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS) {
        cerr << "Failed to get compiled YARA rules." << endl;
        yr_compiler_destroy(compiler);
        yr_finalize();
        return;
    }
    // 사용자 데이터 구조체 생성
    UserData userData { &detectedMalware, &filePath };

    // 스캔
    int scanResult = yr_rules_scan_file(rules, filePath.c_str(), 0, yaraCallbackFunction, &userData, 0);
    if (scanResult != ERROR_SUCCESS && scanResult != CALLBACK_MSG_RULE_NOT_MATCHING) {
        cerr << "Error scanning file " <<filePath <<": " << scanResult << endl;
    }
 
    yr_rules_destroy(rules);
    yr_compiler_destroy(compiler);
    yr_finalize();
}

