#pragma once

#include <string>
#include "error_codes.h"

bool IsDirectory(const std::string& path);
void PrintError(const std::string& message);
void PrintErrorMessage(int code);
bool IsExtension(const std::string& filePath, const std::string& extension);
bool IsELFFile(const std::string& filePath);