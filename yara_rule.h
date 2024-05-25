#pragma once

#include <string>
#include <vector>
#include <yara.h>
#include "scan.h"

int YaraCallbackFunction(YR_SCAN_CONTEXT* context, int message, void* messageData, void* userData);
int CheckYaraRule(const std::string& filePath, std::vector<std::string>& detectedMalware);
int GetRuleFiles(const std::string& directory, std::vector<std::string>& ruleFiles);
