#pragma once

#include <curl/curl.h>
#include <string>

class EmailSender {
public:
    EmailSender(const std::string& smtpServer, int smtpPort, const std::string& emailAddress);
    ~EmailSender();
    int SendEmailWithAttachment();

private:
    std::string m_strSmtpServer;
    int m_nSmtpPort;
    std::string m_strEmailAddress;
    std::string m_strSenderEmail = "udangtang02@gmail.com"; // 고정된 발신자 이메일 주소
    CURL* m_curl;

    std::string GetEmailPassword();
    void InitializeCurl();
    curl_mime* SetupMimeAndCurl(CURL* curl, const std::string& emailPassword, const std::string& body, const std::string& logFilePath, curl_slist* recipients, curl_slist* headers) const;
};
