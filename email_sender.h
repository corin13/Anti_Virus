#pragma once

#include <curl/curl.h>
#include <string>

#define SETTING_FILE "settings.ini"
#define LOG_SAVE_PATH "logs/file_event_monitor_"

#define KEY_SECURITY "security"
#define VALUE_PRIVATE_KEY_PATH "private_key_path"
#define VALUE_ENCRYPTED_PW "encrypted_password"

class EmailSender {
public:
    EmailSender(const std::string& smtpServer, int smtpPort, const std::string& emailAddress);
    ~EmailSender();
    int SendEmailWithAttachment(const std::string& subject, const std::string& body, const std::string& logFilePath);

private:
    std::string m_strSmtpServer;
    int m_nSmtpPort;
    std::string m_strEmailAddress;
    std::string m_strSenderEmail = "udangtang02@gmail.com"; // 고정된 발신자 이메일 주소
    CURL* m_curl;

    std::string GetEmailPassword();
    void InitializeCurl();
    curl_mime* SetupMimeAndCurl(CURL* curl, const std::string& emailPassword, const std::string& subject, const std::string& body, const std::string& logFilePath, curl_slist* recipients, curl_slist* headers) const;
};
