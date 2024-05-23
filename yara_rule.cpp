#include <iostream>
#include "yara_rule.h"

using namespace std;

// YARA 룰 매칭 콜백 함수
int YaraCallbackFunction(YR_SCAN_CONTEXT* context, int message, void* messageData, void* userData) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        auto* data = static_cast<UserData*>(userData);        
        vector<string>* detectedMalware = data->detectedMalware;
        const string* filePath = data->filePath; // 파일 경로 가져오기
        detectedMalware->push_back(*filePath);
        cout << "\n\033[31m[+] Malware detected: [" << *filePath << "]\033[0m\n\n";
    }
    return CALLBACK_CONTINUE;
}



void CheckYaraRule(const string& filePath, vector<string>& detectedMalware) {
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
    // yara rule 파일 열기
    const char* ruleFile = "rules.yara";
    FILE* ruleFilePtr = fopen(ruleFile, "r");
    if (!ruleFilePtr) {
        PrintError("Failed to open YARA rules file.");
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
