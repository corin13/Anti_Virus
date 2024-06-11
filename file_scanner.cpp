#include <csignal>
#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <jsoncpp/json/json.h>
#include "ansi_color.h"
#include "config.h"
#include "file_scanner.h"
#include "malware_hash_checker.h"
#include "yara_checker.h"

#define ALL_FILES 1
#define ELF_FILES 2
#define SPECIFIC_EXTENSION 3

#define YARA_RULE 1
#define HASH_COMPARISON 2

// 전역 변수 추가
bool CFileScanner::m_bStopScanning = false;

// 신호 처리기 함수 추가
void signalHandler(int signal) {
    if (signal == SIGINT) {
        std::cout << "\nScan interrupted. Stopping the scan...\n";
        CFileScanner::m_bStopScanning = true;
    }
}

//-s 혹은 --scan 옵션 입력 시 실행되는 함수
int CFileScanner::StartScan(){
    int nRresult = PerformFileScan();
    if (nRresult != SUCCESS_CODE) {
        PrintErrorMessage(nRresult);
        return nRresult;
    }
    return SUCCESS_CODE;
}


int CFileScanner::StartIniScan(){
    //INI 파일에서 설정 값을 읽어옵니다.
    m_strScanTargetPath = Config::Instance().GetScanPath();
    m_nScanTypeOption = Config::Instance().GetScanType();
    m_strExtension = Config::Instance().GetFileExtension(); // 설정 파일에서 확장자 값을 읽어옴
    m_nFileTypeOption = m_strExtension.empty() ? 1 : 3;
    
    std::cout << "Starting scan on path: " << m_strScanTargetPath << " with scan type: " << m_nScanTypeOption << " and extension: " << m_strExtension << "\n";

    // 스캔을 수행하는 함수 호출
    int result = ScanDirectory();

    if (result != SUCCESS_CODE) {
        PrintErrorMessage(result);
        return result;
    }
    return SUCCESS_CODE;
}


int CFileScanner::PerformFileScan() {
    std::cout << "Please enter the path (Default is '/') : ";
    getline(std::cin, m_strScanTargetPath);

    if(m_strScanTargetPath.empty()) {
        m_strScanTargetPath = "/"; // 경로가 비어있을 경우 디폴트로 '/' 설정
    }
    if (!IsDirectory(m_strScanTargetPath)) { // 경로 유효성 검사
        return ERROR_PATH_NOT_FOUND;
    }

    std::cout << "\n[-] Scan Path : " << m_strScanTargetPath << "\n\n";

        std::cout << "Select a file type to scan:\n\n"
            << "1. All files (Default)\n"
            << "2. Only ELF files\n"
            << "3. Specific file extension\n\n"
            << "Please enter the option: ";
    std::string strFileTypeInput;
    getline(std::cin, strFileTypeInput);

    m_nFileTypeOption = ALL_FILES; // 기본값으로 모든 파일 검사
    if (strFileTypeInput == "3") {
        m_nFileTypeOption = SPECIFIC_EXTENSION;
        std::cout << "Enter the file extension to scan (Default is 'exe'): ";
        getline(std::cin, m_strExtension);
    } else if (strFileTypeInput == "1" || strFileTypeInput == "2") {
        m_nFileTypeOption = std::stoi(strFileTypeInput);
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
    m_nScanTypeOption = (strScanTypeInput.empty() || strScanTypeInput == "1") ? YARA_RULE : HASH_COMPARISON;

    std::cout << "\n### File Scan Start ! (Path : " << m_strScanTargetPath << " , FileTypeOption : " << m_nFileTypeOption << " , ScanTypeOption : " << m_nScanTypeOption << ") ###\n\n";

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

    char * const paths[] = {const_cast<char *>(m_strScanTargetPath.c_str()), nullptr};

    FTS *fileSystem = fts_open(paths, FTS_NOCHDIR | FTS_PHYSICAL, nullptr);
    if (fileSystem == nullptr) {
        return ERROR_CANNOT_OPEN_DIRECTORY;
    }

    FTSENT *node;
    int nResult;
    signal(SIGINT, signalHandler);  // 신호 처리기 등록
    while ((node = fts_read(fileSystem)) != nullptr && !m_bStopScanning) {
        if (node->fts_info == FTS_F) {
            bool shouldScan = false;

            if (m_nFileTypeOption == SPECIFIC_EXTENSION) {
                if(m_strExtension.empty()) {
                    m_strExtension = "exe";
                }
                shouldScan = IsExtension(node->fts_path, m_strExtension);
            } else if (m_nFileTypeOption == ELF_FILES) {
                shouldScan = IsELFFile(node->fts_path);
            } else {
                shouldScan = true;
            }

            if (shouldScan) {
                m_nFileCount++;
                m_llTotalSize += node->fts_statp->st_size;
                std::cout << node->fts_path << "\n";
                std::string strDetectionCause;
                if (m_nScanTypeOption == YARA_RULE) {
                    CYaraChecker IYaraChecker("./yara-rules");
                    nResult = IYaraChecker.CheckYaraRule(node->fts_path, m_vecDetectedMalware, strDetectionCause);
                } else {
                    CMalwareHashChecker IMalwareHashChecker;
                    std::string hashListPath = "./hashes.txt";
                    nResult = IMalwareHashChecker.LoadHashes(hashListPath); // hashes.txt는 악성파일 해시값이 저장되어있는 텍스트 파일(현재는 테스트용으로 test.txt의 해시값이 저장되어 있음)
                    if (nResult != SUCCESS_CODE) {
                        fts_close(fileSystem);
                        return nResult;
                    }
                    nResult = IMalwareHashChecker.CompareByHash(node, m_vecDetectedMalware, strDetectionCause);
                }
                if(!strDetectionCause.empty()) {
                    ST_ScanData data = {
                    .DetectedFile = GetAbsolutePath(node->fts_path),
                    .ScanType = m_nScanTypeOption == YARA_RULE ? "Yara" : "Hash",
                    .YaraRule = m_nScanTypeOption == YARA_RULE ? strDetectionCause : "N/A",
                    .HashValue = m_nScanTypeOption == HASH_COMPARISON ? strDetectionCause : "N/A",
                    .FileSize = "",
                    .Timestamp = GetCurrentTimeWithMilliseconds(),
                    .IsMoved = false,
                    .PathAfterMoving = "N/A"
                    };
                    m_vecScanData.push_back(data);
                }
            }
        }
    }

    signal(SIGINT, SIG_DFL);  // 신호 처리기 기본으로 되돌림

    if (fts_close(fileSystem) < 0) {
        return ERROR_CANNOT_CLOSE_FILE_SYSTEM;
    }

    std::cout << "\n### End File Scan ###\n\n";

        // 파일 검사 종료 시간 기록
    auto stop = std::chrono::high_resolution_clock::now();

    // 소요된 시간 계산 (밀리초 단위)
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
    m_dScanTime = duration.count() / 1000.0;

    // 스캔 결과 출력
    nResult = PrintScanResult();
    if(nResult != SUCCESS_CODE) {
        return nResult;
    }
    // 악성 파일 이동
    nResult = MoveDetectedMalware();

    for(ST_ScanData& data : m_vecScanData) {
        LogResult(data);
    }
    return SUCCESS_CODE;
}

// 검사 결과 출력
int CFileScanner::PrintScanResult() {
        
    std::cout << "\n- File Scan Result -\n\n"
            << COLOR_RED << "[+] Total Malware File : " << m_vecDetectedMalware.size() << " files" << COLOR_RESET << "\n";
    for (int i = 0; i < m_vecDetectedMalware.size(); ++i) {
        std::cout << COLOR_RED << "[" << i + 1 << "] : " << m_vecDetectedMalware[i] << COLOR_RESET << "\n";
    }
    std::cout << "\n[+] Total Scan File : " << m_nFileCount << " files " << m_llTotalSize << " bytes\n";
    std::cout << "\n[+] File scan time :  " << std::fixed << std::setprecision(3) << m_dScanTime << " sec\n";

    return SUCCESS_CODE;
}

// 악성파일로 탐지된 파일들 특정 디렉토리로 이동
int CFileScanner::MoveDetectedMalware() {
    if (!m_vecDetectedMalware.empty()) {
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
            for(ST_ScanData& data : m_vecScanData) {
                int nResult = MoveFile(data, strDestinationDir);
                if(nResult != SUCCESS_CODE) {
                    PrintErrorMessage(nResult);
                }
            }
        }
    }
    return SUCCESS_CODE;
}

// 특정 파일을 이동시키고 로그에 기록
int CFileScanner::MoveFile(ST_ScanData& data, const std::string& destinationDir) {
    try {
        std::string strFileName = data.DetectedFile.substr(data.DetectedFile.find_last_of("/") + 1);
        std::string strDestination = destinationDir + "/" + strFileName;

        // 파일 이동
        if (rename(data.DetectedFile.c_str(), strDestination.c_str()) != 0) {
            return ERROR_CANNOT_MOVE_FILE;
        }

        // 파일 읽기 전용 권한만 부여
        if (chmod(strDestination.c_str(), S_IRUSR) != 0) {
            return ERROR_CANNOT_CHANGE_PERMISSIONS;
        }

        std::cout << "[+] Moved: " << data.DetectedFile << " -> " << GetAbsolutePath(strDestination) << "\n";
        data.IsMoved = true;
        data.PathAfterMoving = GetAbsolutePath(strDestination);

        return SUCCESS_CODE;
    } catch (const std::exception& e) {
        PrintError("Exception occurred while moving file: " + std::string(e.what()));
        return ERROR_UNKNOWN;
    }
}

// 파일 이벤트를 날짜별로 로그에 기록
void CFileScanner::LogResult(ST_ScanData& data) {
    // JSON 객체 생성
    Json::Value logEntry;
    logEntry["timestamp"] = data.Timestamp;
    logEntry["scan_type"] = data.ScanType;
    logEntry["detected_file"] = data.DetectedFile;
    logEntry["hash_value"] = data.HashValue;
    logEntry["yara_rule"] = data.YaraRule;
    logEntry["is_moved"] = data.IsMoved ? "True" : "False";
    logEntry["path_after_moving"] = data.PathAfterMoving;

//시간, 원래 경로, 이동 경로, 해시인지 야라인지, 해시값, 룰 이름, 이동여부, 
    struct stat fileStat;
    const std::string& path = data.IsMoved ? data.PathAfterMoving : data.DetectedFile;
    if (stat(path.c_str(), &fileStat) == 0) {
        logEntry["file_size"] = Json::UInt64(fileStat.st_size);
    } else {
        logEntry["file_size"] = "N/A";
    }
    SaveLogInJson(logEntry, "./logs/file_scanner.log");
}
