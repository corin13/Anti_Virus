#pragma once

#include <string>

bool IsDirectory(const std::string& path);
void PrintError(const std::string& message);
bool IsExtension(const std::string& filePath, const std::string& extension);
bool IsELFFile(const std::string& filePath);