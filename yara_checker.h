#pragma once

#include <string>
#include <vector>
#include <yara.h>

class CYaraChecker {
public:
    CYaraChecker(const std::string& rulesDirectory);
    int CheckYaraRule(const std::string& filePath, std::vector<std::string>& detectedMalware, std::string& detectionCause);

private:
    struct ST_YaraData {
        std::vector<std::string>* DetectedMalware;
        const std::string* FilePath;
        std::string NameOfYaraRule;
    };

    std::string m_strRulesDirectory;
    std::vector<std::string> m_vecRuleFiles;

    static int YaraCallbackFunction(YR_SCAN_CONTEXT* context, int message, void* messageData, void* yaraData);
    int GetRuleFiles();    
};