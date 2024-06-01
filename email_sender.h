#pragma once

#include <curl/curl.h>
#include <string>

class EmailSender {
public:
    EmailSender(const std::string& smtpServer, int smtpPort, const std::string& emailAddress);
    int SendEmailWithAttachment();

private:
    std::string smtpServer;
    int smtpPort;
    std::string emailAddress;

    const char* GetEmailPassword();
    CURL* InitializeCurl() const;
    curl_mime* SetupMimeAndCurl(CURL* curl, const std::string& emailPassword, const std::string& toEmail, const std::string& body, const std::string& logFilePath, curl_slist* recipients, curl_slist* headers) const;
};
