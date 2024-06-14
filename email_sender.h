#pragma once

#include <curl/curl.h>
#include <string>
#include <chrono>


#define SETTING_FILE "settings.ini"

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
    std::string m_strSenderEmail;
    CURL* m_curl;
    std::chrono::time_point<std::chrono::steady_clock> lastEmailSentTime;
    const std::chrono::minutes emailInterval = std::chrono::minutes(5);
    const std::string timeFilePath = "last_email_time.txt"; // 파일 경로

    std::string GetEmailPassword();
    std::string GetSenderEmail();
    void InitializeCurl();
    curl_mime* SetupMimeAndCurl(CURL* curl, const std::string& emailPassword, const std::string& subject, const std::string& body, const std::string& logFilePath, curl_slist* recipients, curl_slist* headers) const;
    void LoadLastEmailSentTime(); // 마지막 이메일 전송 시간 로드
    void SaveLastEmailSentTime(); // 마지막 이메일 전송 시간 저장
};