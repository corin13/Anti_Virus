#include <algorithm>
#include <dirent.h>
#include <iostream>
#include "yara_rule.h"

// YARA 룰 매칭 콜백 함수
int YaraCallbackFunction(YR_SCAN_CONTEXT* context, int message, void* messageData, void* yaraData) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        auto* data = static_cast<ST_YaraData*>(yaraData);        
        std::vector<std::string>* detectedMalware = data->DetectedMalware;
        const std::string* filePath = data->FilePath; // 파일 경로 가져오기
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
int GetRuleFiles(const std::string& directory, std::vector<std::string>& ruleFiles) {
    DIR* dir;
    struct dirent* ent;
    if ((dir = opendir(directory.c_str())) != nullptr) {
        while ((ent = readdir(dir)) != nullptr) {
            if (ent->d_type == DT_REG) { // regular file
                ruleFiles.push_back(directory + "/" + ent->d_name);
            }
        }
        closedir(dir);
        return SUCCESS_CODE;
    } else {
        PrintError("Could not open directory " + directory );
        return ERROR_CANNOT_OPEN_DIRECTORY;
    }
}

int CheckYaraRule(const std::string& filePath, std::vector<std::string>& detectedMalware) {
    YR_COMPILER* compiler = nullptr;
    YR_RULES* rules = nullptr;

    // yara 라이브러리 초기화
    if (yr_initialize() != ERROR_SUCCESS) {
        PrintError("Failed to initialize YARA.");
        return ERROR_YARA_RULE;
    }
    // yara 컴파일러 객체 생성
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        PrintError("Failed to create YARA compiler.");
        yr_finalize();
        return ERROR_YARA_RULE;
    }

    // YARA 룰 파일 리스트
    std::vector<std::string> ruleFiles;
    int result = GetRuleFiles("./yara-rules", ruleFiles);
    if(result != SUCCESS_CODE) {
        yr_compiler_destroy(compiler);
        yr_finalize();
        return result;
    }
    
    // YARA 룰 파일들 추가
    for (const auto& ruleFile : ruleFiles) {
        FILE* ruleFilePtr = fopen(ruleFile.c_str(), "r");
        if (!ruleFilePtr) {
            PrintError("Failed to open YARA rules file.");
            result = ERROR_CANNOT_OPEN_FILE;
            break;
        }
        // yara rule 컴파일
        if (yr_compiler_add_file(compiler, ruleFilePtr, nullptr, ruleFile.c_str()) != 0) {
            PrintError("Failed to compile YARA rules.");
            fclose(ruleFilePtr);
            result = ERROR_YARA_RULE;
            break;
        }
        fclose(ruleFilePtr);
    }
    
    if(result == SUCCESS_CODE) {
        // 컴파일된 룰 가져오기
        if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS) {
            PrintError("Failed to get compiled YARA rules.");
            result =  ERROR_YARA_RULE;
        } else {
            ST_YaraData yaraData { &detectedMalware, &filePath };

            // 스캔
            int scanResult = yr_rules_scan_file(rules, filePath.c_str(), 0, YaraCallbackFunction, &yaraData, 0);
            if (scanResult != ERROR_SUCCESS && scanResult != CALLBACK_MSG_RULE_NOT_MATCHING) {
                PrintError("Error scanning file " + filePath);
                result = ERROR_YARA_RULE;
            }
        }
    }

    if (rules) {
        yr_rules_destroy(rules);
    }
    if (compiler) {
        yr_compiler_destroy(compiler);
    }
    yr_finalize();
    return result;
}
