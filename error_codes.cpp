#include "error_codes.h"

std::string GetErrorMessage(int code) {
    switch (code) {
        case SUCCESS_CODE:
            return "Success";
        case ERROR_INVALID_FUNCTION:
            return "Invalid function";
        case ERROR_FILE_NOT_FOUND:
            return "File not found";
        case ERROR_ACCESS_DENIED:
            return "Access denied";
        case ERROR_CANNOT_OPEN_FILE:
            return "Cannot open file";
        case ERROR_PATH_NOT_FOUND:
            return "Path not found";
        case ERROR_INVALID_OPTION:
            return "Invalid option";
        case ERROR_CANNOT_CLOSE_FILE_SYSTEM:
            return "Failed to close file system";
        case ERROR_CANNOT_MOVE_FILE:
            return "Failed to move file";
        case ERROR_CANNOT_CHANGE_PERMISSIONS:
            return "Failed to change file permissions";
        case ERROR_CANNOT_OPEN_DIRECTORY:
            return "Failed to open directory";
        case ERROR_CANNOT_COMPUTE_HASH:
            return "Failed to compute hash for file";
        case ERROR_INVALID_RANGE:
            return "Invalid range for substring extraction";
        case ERROR_CANNOT_WRITE_FILE:
            return "Failed to write data to file";
        case ERROR_YARA_LIBRARY:
            return "YARA library error";
        case ERROR_CANNOT_REMOVE_FILE:
            return "Failed to remove file";
        case ERROR_CANNOT_SEND_EMAIL:
            return "Failed to send email";
        case ERROR_IPTABLES_COMMAND:
            return "Failed to execute iptables";
        case ERROR_LOG_OPERATION_FAILED:
            return "Failed logging operation";
        case ERROR_CANNOT_FIND_INTERFACE:
            return "Failed to find interface";
        case ERROR_CANNOT_OPEN_DEVICE:
            return "Failed to open device";
        case ERROR_DATABASE_GENERAL:
            return "Database error";
        case ERROR_INVALID_INPUT:
            return "INVALID_INPUT";
        case ERROR_UNKNOWN:
        default:
            return "Unknown error";
    }
}