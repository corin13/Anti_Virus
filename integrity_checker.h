#pragma once

#include <string>

std::string CalculateFileHash(const std::string &filePath);
std::string RetrieveStoredHash(const std::string &filePath);
void SaveFileHash(const std::string &filePath);
void RemoveFileHash(const std::string &filePath);