#pragma once

#include <string>
#include <ctime>
#include <jsoncpp/json/json.h>
#include "error_codes.h"

#define BUFFER_SIZE 8192

bool IsDirectory(const std::string& path);
void PrintInputError(std::string& error);
void PrintError(const std::string& message);
void PrintErrorMessage(int code, const std::string& context = "");
void HandleError(int code, const std::string& context = "");
bool IsExtension(const std::string& filePath, const std::string& extension);
bool IsELFFile(const std::string& filePath);
int ComputeSHA256(const std::string& fileName, std::string& fileHash);
std::time_t GetCurrentTime();
std::string GetCurrentTimeWithMilliseconds();
std::string Trim(const std::string& str);
std::string GetAbsolutePath(std::string path);
void SaveLogInJson(Json::Value logEntry, std::string logFilePath);