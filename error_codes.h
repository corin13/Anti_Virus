#pragma once

#include <string>

enum ErrorCode {
    SUCCESS_CODE = 0,
    ERROR_INVALID_FUNCTION,
    ERROR_FILE_NOT_FOUND,
    ERROR_ACCESS_DENIED,
    ERROR_CANNOT_OPEN_FILE,
    ERROR_PATH_NOT_FOUND,
    ERROR_INVALID_OPTION,
    ERROR_CANNOT_CLOSE_FILE_SYSTEM,
    ERROR_CANNOT_MOVE_FILE,
    ERROR_CANNOT_CHANGE_PERMISSIONS,
    ERROR_CANNOT_OPEN_DIRECTORY,
    ERROR_CANNOT_COMPUTE_HASH,
    ERROR_INVALID_RANGE,
    ERROR_CANNOT_WRITE_FILE,
    ERROR_YARA_RULE,
    ERROR_UNKNOWN
};

std::string GetErrorMessage(int code);

