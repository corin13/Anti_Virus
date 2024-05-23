#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include <fstream>
#include <chrono>
#include <iomanip>
#include "scan.h"
#include "malware_hash.h"
#include "yara_rule.h"

//-s 혹은 --scan 옵션 입력 시 실행되는 함수
int StartScan(){
    int result = PerformFileScan();
    if (result != SUCCESS_CODE) {
        PrintErrorMessage(result);
        return result;
    }
    return SUCCESS_CODE;
}

int PerformFileScan() {
    std::cout << "Please enter the path (Default is '/') : ";
    std::string path;
    getline(std::cin, path);

    if(path.empty()) {
        path = "/"; // 경로가 비어있을 경우 디폴트로 '/' 설정
    }
    if (!IsDirectory(path)) { // 경로 유효성 검사
        return ERROR_PATH_NOT_FOUND;
    }

    std::cout << "\n[-] Scan Path : " << path << "\n\n";

        std::cout << "Select a file type to scan:\n\n"
            << "1. Specific file extension\n"
            << "2. Only ELF files\n"
            << "3. All files (Default)\n\n"
            << "Please enter the option: ";
    std::string fileTypeInput;
    getline(std::cin, fileTypeInput);

    int fileTypeOption = 3; // 기본값으로 모든 파일 검사
    std::string extension;
    if (fileTypeInput == "1") {
        fileTypeOption = 1;
        std::cout << "Enter the file extension to scan (Default is 'exe'): ";
        getline(std::cin, extension);
    } else if (fileTypeInput == "2" || fileTypeInput == "3") {
        fileTypeOption = std::stoi(fileTypeInput);
    } else if (!fileTypeInput.empty()) {
        return ERROR_INVALID_OPTION;
    }

    std::cout << "\nSelect a malware scan option:\n\n"
            << "1. YARA rule (Default)\n"
            << "2. Simple file hash comparison\n\n"
            << "Please enter the option : ";
    std::string scanTypeInput;
    getline(std::cin, scanTypeInput);

    if (scanTypeInput != "1" && scanTypeInput != "2" && !scanTypeInput.empty()) {
        return ERROR_INVALID_OPTION;
    }
    int scanTypeOption = (scanTypeInput.empty() || scanTypeInput == "1") ? 1 : 2;

    std::cout << "\n### File Scan Start ! (Path : " << path << " , FileTypeOption : " << fileTypeOption << " , ScanTypeOption : " << scanTypeOption << ") ###\n\n";

    ScanData scanData = {{}, path, 0, 0, 0.0};
    int result = ScanDirectory(scanData, scanTypeOption, fileTypeOption, extension);
    if (result != SUCCESS_CODE) {
        return result;
    }
    return SUCCESS_CODE;
}


// 사용자가 입력한 디렉토리와 옵션에 맞게 파일을 순회하며 악석파일 검사
int ScanDirectory(ScanData& scanData, int scanTypeOption, int fileTypeOption, std::string& extension) {

    // 파일 검사 시작 시간 기록
    auto start = std::chrono::high_resolution_clock::now();

    char * const paths[] = {const_cast<char *>(scanData.filePath.c_str()), nullptr};

    FTS *fileSystem = fts_open(paths, FTS_NOCHDIR | FTS_PHYSICAL, nullptr);
    if (fileSystem == nullptr) {
        return ERROR_CANNOT_OPEN_DIRECTORY;
    }

    FTSENT *node;
    std::vector<std::string> hashes;
    int result = LoadHashes("hashes.txt", hashes); // hashes.txt는 악성파일 해시값이 저장되어있는 텍스트 파일(현재는 테스트용으로 test.txt의 해시값이 저장되어 있음)
    if (result != SUCCESS_CODE) {
        return result;
    }

    while ((node = fts_read(fileSystem)) != nullptr) {
        if (node->fts_info == FTS_F) {
            bool shouldScan = false;

            if (fileTypeOption == 1) {
                if(extension.empty()) {
                    extension = "exe";
                }
                shouldScan = IsExtension(node->fts_path, extension);
            } else if (fileTypeOption == 2) {
                shouldScan = IsELFFile(node->fts_path);
            } else {
                shouldScan = true;
            }

            if (shouldScan) {
                scanData.fileCount++;
                scanData.totalSize += node->fts_statp->st_size;
                std::cout << node->fts_path << "\n";
                if (scanTypeOption == 1) {
                    CheckYaraRule(node->fts_path, scanData.detectedMalware);
                } else {
                    CompareByHash(node, scanData.detectedMalware, hashes);
                }
            }
        }
    }

    if (fts_close(fileSystem) < 0) {
        return ERROR_CANNOT_CLOSE_FILE_SYSTEM;
    }

    std::cout << "\n### End File Scan ###\n\n";

        // 파일 검사 종료 시간 기록
    auto stop = std::chrono::high_resolution_clock::now();

    // 소요된 시간 계산 (밀리초 단위)
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
    scanData.scanTime = duration.count() / 1000.0;

    // 스캔 결과 출력
    result = PrintScanResult(scanData);
    if(result != SUCCESS_CODE) {
        return result;
    }
    // 악성 파일 이동
    result = MoveDetectedMalware(scanData.detectedMalware);

    return SUCCESS_CODE;
}

// 검사 결과 출력
int PrintScanResult(const ScanData& scanData) {
        
    std::cout << "\n- File Scan Result -\n\n"
            << "\033[31m[+] Total Malware File : " << scanData.detectedMalware.size() << " files\033[0m\n";
    for (int i = 0; i < scanData.detectedMalware.size(); ++i) {
        std::cout << "\033[31m[" << i + 1 << "] : " << scanData.detectedMalware[i] << "\033[0m\n";
    }
    std::cout << "\n[+] Total Scan File : " << scanData.fileCount << " files " << scanData.totalSize << " bytes\n";
    std::cout << "\n[+] File scan time :  " << std::fixed << std::setprecision(3) << scanData.scanTime << " sec\n";

    return SUCCESS_CODE;
}

// 악성파일로 탐지된 파일들 특정 디렉토리로 이동
int MoveDetectedMalware(const std::vector<std::string>& detectedMalware) {
    if (!detectedMalware.empty()) {
        std::cout << "\nWould you like to move all detected malware files? (Y/n): ";
        std::string input;
        getline(std::cin, input);

        if (input == "y" || input.empty()) { // 기본값으로 엔터 입력을 y로 처리
            // 이동할 디렉토리 설정
            std::string destinationDir = "./detected-malware";
            if (!IsDirectory(destinationDir)) {
                if (mkdir(destinationDir.c_str(), 0700) != 0) {  // 관리자만 접근 가능
                    return ERROR_CANNOT_OPEN_DIRECTORY;
                }
            }

            // 발견된 모든 악성 파일을 이동
            for (const auto& malwareFile : detectedMalware) {
                int result = MoveFile(malwareFile, destinationDir);
                if(result != SUCCESS_CODE) {
                    return result;
                }
                std::cout << "[+] Moved: " << malwareFile << "\n";
            }
        }
    }
    return SUCCESS_CODE;
}

// 특정 파일을 이동시키고 로그에 기록
int MoveFile(const std::string& filePath, const std::string& destinationDir) {
    try {
        std::string fileName = filePath.substr(filePath.find_last_of("/") + 1);
        std::string destination = destinationDir + "/" + fileName;

        // 파일 이동
        if (rename(filePath.c_str(), destination.c_str()) != 0) {
            return ERROR_CANNOT_MOVE_FILE;
        }

        // 파일 읽기 전용 권한만 부여
        if (chmod(destination.c_str(), S_IRUSR) != 0) {
            return ERROR_CANNOT_CHANGE_PERMISSIONS;
        }

        // 파일 이동 로그 기록 (로그 파일이 없으면 생성)
        std::ofstream logFile(destinationDir + "/detected-malware.log", std::ios::out | std::ios::app);
        if (!logFile) {
            return ERROR_CANNOT_OPEN_FILE;
        }
        logFile << filePath << " -> " << destination << "\n";
        logFile.close();

        return SUCCESS_CODE;
    } catch (const std::exception& e) {
        PrintError("Exception occurred while moving file: " + std::string(e.what()));
        return ERROR_UNKNOWN;
    }
}
