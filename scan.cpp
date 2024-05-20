#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include <fstream>
#include "scan.h"
#include "hash.h"
#include "yara_rule.h"

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

    // 악성 파일 격리
    quarantineDetectedMalware(detectedMalware);
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


void printError(const string& message) {
    cerr << "\n\033[31m" << message << "\033[0m\n";
}

void quarantineDetectedMalware(const vector<string>& detectedMalware) {
    if (!detectedMalware.empty()) {
        cout << "\nWould you like to quarantine all detected malware files? (Y/n): ";
        string userResponse;
        getline(cin, userResponse);

        if (userResponse == "y" || userResponse.empty()) { // 기본값으로 엔터 입력을 y로 처리
            // 격리 디렉토리 설정
            string quarantineDir = "./quarantine";
            if (!isDirectory(quarantineDir)) {
                if (mkdir(quarantineDir.c_str(), 0700) != 0) {  // 관리자만 접근 가능
                    printError("Failed to create quarantine directory.");
                    return;
                }
            }

            // 발견된 모든 악성 파일을 격리
            for (const auto& malwareFile : detectedMalware) {
                if (quarantineFile(malwareFile, quarantineDir)) {
                    cout << "[+] Quarantined: " << malwareFile << "\n";
                }
            }
        }
    }
}

bool quarantineFile(const string& filePath, const string& quarantineDir) {
    try {
        string filename = filePath.substr(filePath.find_last_of("/") + 1);
        string destination = quarantineDir + "/" + filename;

        // 파일 이동
        if (rename(filePath.c_str(), destination.c_str()) != 0) {
            printError("Failed to move file to quarantine directory: " + filePath);
            return false;
        }

        // 파일 읽기 전용 권한만 부여
        if (chmod(destination.c_str(), S_IRUSR) != 0) {
            printError("Failed to change file permissions: " + destination);
            return false;
        }

        // 격리 로그 기록 (파일이 없으면 생성)
        ofstream logFile(quarantineDir + "/quarantine.log", ios::out | ios::app);
        if (!logFile) {
            printError("Failed to open quarantine log file.");
            return false;
        }
        logFile << filePath << " -> " << destination << "\n";
        logFile.close();

        return true;
    } catch (const exception& e) {
        printError("Exception occurred while quarantining file: " + string(e.what()));
        return false;
    }
}
