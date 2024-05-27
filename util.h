#pragma once

#include <string>
#include "error_codes.h"

bool IsDirectory(const std::string& path);
void PrintError(const std::string& message);
void PrintErrorMessage(int code);
void HandleError(int code, const std::string& context = "");
bool IsExtension(const std::string& filePath, const std::string& extension);
bool IsELFFile(const std::string& filePath);
int ComputeSHA256(const std::string& fileName, std::string& fileHash);