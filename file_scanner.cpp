#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include <fstream>
#include <chrono>
#include <iomanip>
#include "file_scanner.h"
#include "malware_hash_checker.h"
#include "yara_checker.h"

//-s 혹은 --scan 옵션 입력 시 실행되는 함수
int CFileScanner::StartScan(){
    int nRresult = PerformFileScan();
    if (nRresult != SUCCESS_CODE) {
        PrintErrorMessage(nRresult);
        return nRresult;
    }
    return SUCCESS_CODE;
}

int CFileScanner::PerformFileScan() {
    std::cout << "Please enter the path (Default is '/') : ";
    getline(std::cin, m_scanTargetPath);

    if(m_scanTargetPath.empty()) {
        m_scanTargetPath = "/"; // 경로가 비어있을 경우 디폴트로 '/' 설정
    }
    if (!IsDirectory(m_scanTargetPath)) { // 경로 유효성 검사
        return ERROR_PATH_NOT_FOUND;
    }

    std::cout << "\n[-] Scan Path : " << m_scanTargetPath << "\n\n";

        std::cout << "Select a file type to scan:\n\n"
            << "1. All files (Default)\n"
            << "2. Only ELF files\n"
            << "3. Specific file extension\n\n"
            << "Please enter the option: ";
    std::string strFileTypeInput;
    getline(std::cin, strFileTypeInput);

    m_fileTypeOption = 3; // 기본값으로 모든 파일 검사
    if (strFileTypeInput == "1") {
        m_fileTypeOption = 1;
        std::cout << "Enter the file extension to scan (Default is 'exe'): ";
        getline(std::cin, m_extension);
    } else if (strFileTypeInput == "2" || strFileTypeInput == "3") {
        m_fileTypeOption = std::stoi(strFileTypeInput);
    } else if (!strFileTypeInput.empty()) {
        return ERROR_INVALID_OPTION;
    }

    std::cout << "\nSelect a malware scan option:\n\n"
            << "1. YARA rule (Default)\n"
            << "2. Simple file hash comparison\n\n"
            << "Please enter the option : ";
    std::string strScanTypeInput;
    getline(std::cin, strScanTypeInput);

    if (strScanTypeInput != "1" && strScanTypeInput != "2" && !strScanTypeInput.empty()) {
        return ERROR_INVALID_OPTION;
    }
    m_scanTypeOption = (strScanTypeInput.empty() || strScanTypeInput == "1") ? 1 : 2;

    std::cout << "\n### File Scan Start ! (Path : " << m_scanTargetPath << " , FileTypeOption : " << m_fileTypeOption << " , ScanTypeOption : " << m_scanTypeOption << ") ###\n\n";

    int nResult = ScanDirectory();
    if (nResult != SUCCESS_CODE) {
        return nResult;
    }
    return SUCCESS_CODE;
}


// 사용자가 입력한 디렉토리와 옵션에 맞게 파일을 순회하며 악석파일 검사
int CFileScanner::ScanDirectory() {

    // 파일 검사 시작 시간 기록
    auto start = std::chrono::high_resolution_clock::now();

    char * const paths[] = {const_cast<char *>(m_scanTargetPath.c_str()), nullptr};

    FTS *fileSystem = fts_open(paths, FTS_NOCHDIR | FTS_PHYSICAL, nullptr);
    if (fileSystem == nullptr) {
        return ERROR_CANNOT_OPEN_DIRECTORY;
    }

    FTSENT *node;
    int nResult;
    while ((node = fts_read(fileSystem)) != nullptr) {
        if (node->fts_info == FTS_F) {
            bool shouldScan = false;

            if (m_fileTypeOption == 1) {
                if(m_extension.empty()) {
                    m_extension = "exe";
                }
                shouldScan = IsExtension(node->fts_path, m_extension);
            } else if (m_fileTypeOption == 2) {
                shouldScan = IsELFFile(node->fts_path);
            } else {
                shouldScan = true;
            }

            if (shouldScan) {
                m_fileCount++;
                m_totalSize += node->fts_statp->st_size;
                std::cout << node->fts_path << "\n";
                if (m_scanTypeOption == 1) {
                    nResult = CheckYaraRule(node->fts_path, m_detectedMalware);
                } else {
                    CMalwareHashChecker IMalwareHashChecker;
                    std::string hashListPath = "./hashes.txt";
                    nResult = IMalwareHashChecker.LoadHashes(hashListPath); // hashes.txt는 악성파일 해시값이 저장되어있는 텍스트 파일(현재는 테스트용으로 test.txt의 해시값이 저장되어 있음)
                    if (nResult != SUCCESS_CODE) {
                        fts_close(fileSystem);
                        return nResult;
                    }
                    nResult = IMalwareHashChecker.CompareByHash(node, m_detectedMalware);
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
    m_scanTime = duration.count() / 1000.0;

    // 스캔 결과 출력
    nResult = PrintScanResult();
    if(nResult != SUCCESS_CODE) {
        return nResult;
    }
    // 악성 파일 이동
    nResult = MoveDetectedMalware();

    return SUCCESS_CODE;
}

// 검사 결과 출력
int CFileScanner::PrintScanResult() {
        
    std::cout << "\n- File Scan Result -\n\n"
            << "\033[31m[+] Total Malware File : " << m_detectedMalware.size() << " files\033[0m\n";
    for (int i = 0; i < m_detectedMalware.size(); ++i) {
        std::cout << "\033[31m[" << i + 1 << "] : " << m_detectedMalware[i] << "\033[0m\n";
    }
    std::cout << "\n[+] Total Scan File : " << m_fileCount << " files " << m_totalSize << " bytes\n";
    std::cout << "\n[+] File scan time :  " << std::fixed << std::setprecision(3) << m_scanTime << " sec\n";

    return SUCCESS_CODE;
}

// 악성파일로 탐지된 파일들 특정 디렉토리로 이동
int CFileScanner::MoveDetectedMalware() {
    if (!m_detectedMalware.empty()) {
        std::cout << "\nWould you like to move all detected malware files? (Y/n): ";
        std::string input;
        getline(std::cin, input);

        if (input == "y" || input.empty()) { // 기본값으로 엔터 입력을 y로 처리
            // 이동할 디렉토리 설정
            std::string strDestinationDir = "./detected-malware";
            if (!IsDirectory(strDestinationDir)) {
                if (mkdir(strDestinationDir.c_str(), 0700) != 0) {  // 관리자만 접근 가능
                    return ERROR_CANNOT_OPEN_DIRECTORY;
                }
            }

            // 발견된 모든 악성 파일을 이동
            for (const auto& malwareFilePath : m_detectedMalware) {
                int nResult = MoveFile(malwareFilePath, strDestinationDir);
                if(nResult != SUCCESS_CODE) {
                    PrintErrorMessage(nResult);
                }
                std::cout << "[+] Moved: " << malwareFilePath << "\n";
            }
        }
    }
    return SUCCESS_CODE;
}

// 특정 파일을 이동시키고 로그에 기록
int CFileScanner::MoveFile(const std::string& filePath, const std::string& destinationDir) {
    try {
        std::string strFileName = filePath.substr(filePath.find_last_of("/") + 1);
        std::string strDestination = destinationDir + "/" + strFileName;

        // 파일 이동
        if (rename(filePath.c_str(), strDestination.c_str()) != 0) {
            return ERROR_CANNOT_MOVE_FILE;
        }

        // 파일 읽기 전용 권한만 부여
        if (chmod(strDestination.c_str(), S_IRUSR) != 0) {
            return ERROR_CANNOT_CHANGE_PERMISSIONS;
        }

        // 파일 이동 로그 기록 (로그 파일이 없으면 생성)
        std::ofstream logFile(destinationDir + "/detected-malware.log", std::ios::out | std::ios::app);
        if (!logFile) {
            return ERROR_CANNOT_OPEN_FILE;
        }
        logFile << filePath << " -> " << strDestination << "\n";
        logFile.close();

        return SUCCESS_CODE;
    } catch (const std::exception& e) {
        PrintError("Exception occurred while moving file: " + std::string(e.what()));
        return ERROR_UNKNOWN;
    }
}
