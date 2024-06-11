#pragma once

#include <string>
#include <vector>
#include <yara.h>

class CYaraChecker {
public:
    CYaraChecker(const std::string& rulesDirectory);
    int CheckYaraRule(const std::string& filePath, std::vector<std::string>& detectedMalware, std::string& strDetectionCause);

private:
    struct ST_YaraData {
        std::vector<std::string>* DetectedMalware;
        const std::string* FilePath;
        std::string NameOfYaraRule;
    };

    std::string rulesDirectory;
    std::vector<std::string> ruleFiles;
    static int YaraCallbackFunction(YR_SCAN_CONTEXT* context, int message, void* messageData, void* yaraData);
    int GetRuleFiles(const std::string& directory, std::vector<std::string>& ruleFiles);    
};