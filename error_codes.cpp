#include "error_codes.h"

std::string GetErrorMessage(int code) {
    switch (code) {
        case 0:
            return "Success";
        case 1:
            return "Invalid function";
        case 2:
            return "File not found";
        case 3:
            return "Access denied";
        case 4:
            return "Cannot open file";
        case 5:
            return "Path not found";
        case 6:
            return "Invalid option";
        case 7:
            return "Failed to close file system";
        case 8:
            return "Failed to move file";
        case 9:
            return "Failed to change file permissions";
        case 10:
            return "Failed to open directory";
        case 11:
            return "Failed to compute hash for file";
        case 12:
            return "Invalid range for substring extraction";
        case 13:
            return "Failed to write data to file";
        case 14:
            return "YARA rule error";
        case 15:
            return "Failed to remove file";
        case 16:
            return "Failed to send email";
        case 17:
            return "Failed to execute iptables";
        case 18:
        default:
            return "Unknown error";
    }
}
