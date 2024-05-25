#include <algorithm>
#include <dirent.h>
#include <iostream>
#include "yara_rule.h"

// YARA 룰 매칭 콜백 함수
int YaraCallbackFunction(YR_SCAN_CONTEXT* context, int message, void* messageData, void* userData) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        auto* data = static_cast<UserData*>(userData);        
        std::vector<std::string>* detectedMalware = data->detectedMalware;
        const std::string* filePath = data->filePath; // 파일 경로 가져오기
        YR_RULE* rule = (YR_RULE*)messageData; // 탐지된 룰 정보 가져오기
        // 중복 검사
        if (std::find(detectedMalware->begin(), detectedMalware->end(), *filePath) == detectedMalware->end()) {
            detectedMalware->push_back(*filePath);
            std::cout << "\n\033[31m[+] Malware detected: [" << *filePath << "]\033[0m\n";
            std::cout << "\033[31m[+] Detected by rule: [" << rule->identifier << "]\033[0m\n\n";
        }
    }
    return CALLBACK_CONTINUE;
}

// 디렉토리 내 YARA 룰 파일들을 가져오는 함수
std::vector<std::string> GetRuleFiles(const std::string& directory) {
    std::vector<std::string> ruleFiles;
    DIR* dir;
    struct dirent* ent;
    if ((dir = opendir(directory.c_str())) != nullptr) {
        while ((ent = readdir(dir)) != nullptr) {
            if (ent->d_type == DT_REG) { // regular file
                ruleFiles.push_back(directory + "/" + ent->d_name);
            }
        }
        closedir(dir);
    } else {
        std::cerr << "\033[31m[-] Error: Could not open directory " << directory << "\033[0m" << std::endl;
    }
    return ruleFiles;
}

void CheckYaraRule(const std::string& filePath, std::vector<std::string>& detectedMalware) {
    YR_COMPILER* compiler = nullptr;
    YR_RULES* rules = nullptr;

    // yara 라이브러리 초기화
    if (yr_initialize() != ERROR_SUCCESS) {
        PrintError("Failed to initialize YARA.");
        return;
    }
    // yara 컴파일러 객체 생성
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        PrintError("Failed to create YARA compiler.");
        yr_finalize();
        return;
    }

    // YARA 룰 파일 리스트
    std::vector<std::string> ruleFiles = GetRuleFiles("./yara-rules");
    
    // YARA 룰 파일들 추가
    for (const auto& ruleFile : ruleFiles) {
        FILE* ruleFilePtr = fopen(ruleFile.c_str(), "r");
        if (!ruleFilePtr) {
            PrintError("Failed to open YARA rules file.");
            yr_compiler_destroy(compiler);
            yr_finalize();
            return;
        }
        // yara rule 컴파일
        if (yr_compiler_add_file(compiler, ruleFilePtr, nullptr, ruleFile.c_str()) != 0) {
            PrintError("Failed to compile YARA rules.");
            fclose(ruleFilePtr);
            yr_compiler_destroy(compiler);
            yr_finalize();
            return;
        }
        fclose(ruleFilePtr);
    }
    
    // 컴파일된 룰 가져오기
    if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS) {
        PrintError("Failed to get compiled YARA rules.");
        yr_compiler_destroy(compiler);
        yr_finalize();
        return;
    }
    // 사용자 데이터 구조체 생성
    UserData userData { &detectedMalware, &filePath };

    // 스캔
    int scanResult = yr_rules_scan_file(rules, filePath.c_str(), 0, YaraCallbackFunction, &userData, 0);
    if (scanResult != ERROR_SUCCESS && scanResult != CALLBACK_MSG_RULE_NOT_MATCHING) {
        PrintError("Error scanning file " + filePath);
    }

    yr_rules_destroy(rules);
    yr_compiler_destroy(compiler);
    yr_finalize();
}
