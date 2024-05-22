#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include <fstream>
#include <chrono>
#include <iomanip>
#include "scan.h"
#include "malware_hash.h"
#include "yara_rule.h"

//-s 혹은 --scan 옵션 입력 시 scan() 함수 실행됨
void StartScan(){
    std::cout << "Please enter the path (Default is '/') : ";
    std::string path;
    getline(std::cin, path);

    if(path.empty()) {
        path = "/"; // 경로가 비어있을 경우 디폴트로 '/' 설정
    }
    if (!IsDirectory(path)) { // 경로 유효성 검사
        PrintError("Invalid path. Please enter a valid directory path.");
        return;
    }

    std::cout << "\n[-] Scan Path : " << path << "\n\n";

    std::cout << "Select a malware scan option:\n\n"
            << "1. YARA rule (Default)\n"
            << "2. Simple file hash comparison\n\n"
            << "Please enter the option : ";
    std::string input;
    getline(std::cin, input);

    if (input != "1" && input != "2" && !input.empty()) {
        PrintError("Invalid option selected. Please enter 1 or 2.");
        return; // 잘못된 입력일 경우 함수 종료
    }

    int option = (input.empty() || input == "1") ? 1 : 2;

    std::cout << "\n### File Scan Start ! (Path : " << path << " , Option : " << option << ") ###\n\n";

    // 사용자가 지정한 디렉토리 내의 모든 파일을 순회하면서 악석파일 검사
    ScanDirectory(path, option);

    return;
}



void ScanDirectory(const std::string& path, int option) {

    // 파일 검사 시작 시간 기록
    auto start = std::chrono::high_resolution_clock::now();

    char * const paths[] = {const_cast<char *>(path.c_str()), nullptr};

    FTS *fileSystem = fts_open(paths, FTS_NOCHDIR | FTS_PHYSICAL, nullptr);
    if (fileSystem == NULL) {
        PrintError("Failed to open the directory path.");
        return;
    }

    FTSENT *node;
    int fileCount = 0;
    long long totalSize = 0;
    std::vector<std::string> detectedMalware; // 악성파일로 판별된 파일의 경로를 저장
    std::vector<std::string> hashes = LoadHashes("hashes.txt"); // hashes.txt는 악성파일 해시값이 저장되어있는 텍스트 파일(현재는 테스트용으로 test.txt의 해시값이 저장되어 있음)

    // 파일을 한개씩 순회해서 사용자가 입력한 옵션에 따라 검사
    if(option == 1) {
        while ((node = fts_read(fileSystem)) != nullptr) {
            if (node->fts_info == FTS_F) {
                fileCount++;
                totalSize += node->fts_statp->st_size;
                std::cout << node->fts_path << "\n";
                CheckYaraRule(node->fts_path, detectedMalware);
            }
        }    
    }
    else if(option == 2) {
        while ((node = fts_read(fileSystem)) != nullptr) {
            if (node->fts_info == FTS_F) {
                fileCount++;
                totalSize += node->fts_statp->st_size;
                std::cout << node->fts_path << "\n";
                CompareByHash(node, detectedMalware, hashes);
            }
        }
    }

    if (fts_close(fileSystem) < 0) {
        PrintError("Failed to close the file system.");
    }

    std::cout << "\n### End File Scan ###\n\n";

        // 파일 검사 종료 시간 기록
    auto stop = std::chrono::high_resolution_clock::now();

    // 소요된 시간 계산 (밀리초 단위)
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
    double seconds = duration.count() / 1000.0;

    // 스캔 결과 출력
    std::cout << "\n- File Scan Result -\n\n"
            << "\033[31m[+] Total Malware File : " << detectedMalware.size() << " files\033[0m\n";
    for (int i = 0; i < detectedMalware.size(); ++i) {
        std::cout << "\033[31m[" << i + 1 << "] : " << detectedMalware[i] << "\033[0m\n";
    }
    std::cout << "\n[+] Total Scan File : " << fileCount << " files " << totalSize << " bytes\n";
    std::cout << "\n[+] File scan time :  " << std::fixed << std::setprecision(3) << seconds << " sec (" << duration.count() << " ms)\n";

    // 악성 파일 이동
    MoveDetectedMalware(detectedMalware);
}


void MoveDetectedMalware(const std::vector<std::string>& detectedMalware) {
    if (!detectedMalware.empty()) {
        std::cout << "\nWould you like to move all detected malware files? (Y/n): ";
        std::string input;
        getline(std::cin, input);

        if (input == "y" || input.empty()) { // 기본값으로 엔터 입력을 y로 처리
            // 이동할 디렉토리 설정
            std::string destinationDir = "./detected-malware";
            if (!IsDirectory(destinationDir)) {
                if (mkdir(destinationDir.c_str(), 0700) != 0) {  // 관리자만 접근 가능
                    PrintError("Failed to create detected-malware directory.");
                    return;
                }
            }

            // 발견된 모든 악성 파일을 이동
            for (const auto& malwareFile : detectedMalware) {
                if (MoveFile(malwareFile, destinationDir)) {
                    std::cout << "[+] Moved: " << malwareFile << "\n";
                }
            }
        }
    }
}

bool MoveFile(const std::string& filePath, const std::string& destinationDir) {
    try {
        std::string fileName = filePath.substr(filePath.find_last_of("/") + 1);
        std::string destination = destinationDir + "/" + fileName;

        // 파일 이동
        if (rename(filePath.c_str(), destination.c_str()) != 0) {
            PrintError("Failed to move file to detected-malware directory: " + filePath);
            return false;
        }

        // 파일 읽기 전용 권한만 부여
        if (chmod(destination.c_str(), S_IRUSR) != 0) {
            PrintError("Failed to change file permissions: " + destination);
            return false;
        }

        // 파일 이동 로그 기록 (로그 파일이 없으면 생성)
        std::ofstream logFile(destinationDir + "/detected-malware.log", std::ios::out | std::ios::app);
        if (!logFile) {
            PrintError("Failed to open detected-malware log file.");
            return false;
        }
        logFile << filePath << " -> " << destination << "\n";
        logFile.close();

        return true;
    } catch (const std::exception& e) {
        PrintError("Exception occurred while moving file: " + std::string(e.what()));
        return false;
    }
}
