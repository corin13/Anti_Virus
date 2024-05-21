#pragma once

#include <string>
#include <vector>
#include <yara.h>
#include "scan.h"

int yaraCallbackFunction(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data);
void checkYaraRule(const std::string& filePath, std::vector<std::string>& detectedMalware);

