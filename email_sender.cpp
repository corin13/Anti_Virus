#include <cstdlib>
#include <string>
#include <fstream>
#include <iostream>
#include "email_sender.h"
#include "event_monitor.h"
#include "ini.h"
#include "secure_config.h"
#include "util.h"

#define SETTING_FILE "settings.ini"
#define LOG_SAVE_PATH "logs/file_event_monitor_"

#define KEY_SECURITY "security"
#define VALUE_PRIVATE_KEY_PATH "private_key_path"
#define VALUE_ENCRYPTED_PW "encrypted_password"

EmailSender::EmailSender(const std::string& smtpServer, int smtpPort, const std::string& emailAddress)
    : m_strSmtpServer(smtpServer), m_nSmtpPort(smtpPort), m_strEmailAddress(emailAddress) {}

EmailSender::~EmailSender() {
    if (m_curl) {
        curl_easy_cleanup(m_curl);
    }
}

// 암호화된 이메일 비밀번호를 복호화해서 가져오기
std::string EmailSender::GetEmailPassword() {
    try {
        INIReader reader(SETTING_FILE);
        if (reader.ParseError() != 0) {
            throw std::runtime_error("Failed to load ini file");
        }

        std::string strPrivateKeyPath = reader.Get(KEY_SECURITY, VALUE_PRIVATE_KEY_PATH, "");
        if (strPrivateKeyPath.empty()) {
            throw std::runtime_error("Private key path not found in ini file");
        }

        CSecureConfig ISecurityconfig(SETTING_FILE, strPrivateKeyPath);
        std::string decrypted_password = ISecurityconfig.getDecryptedPassword(KEY_SECURITY, VALUE_ENCRYPTED_PW);
        return decrypted_password;
    } catch (const std::exception& e) {
        PrintError(e.what());
        return "";
    }
}

// curl 초기화
void EmailSender::InitializeCurl() {
    m_curl = curl_easy_init();
    if (!m_curl) {
        HandleError(ERROR_INVALID_FUNCTION, "Failed to initialize libcurl.");
    }
}

// MIME 메시지 생성 및 curl 옵션 설정
curl_mime* EmailSender::SetupMimeAndCurl(CURL* curl, const std::string& emailPassword, const std::string& body, const std::string& logFilePath, curl_slist* recipients, curl_slist* headers) const {
    // MIME 메시지 생성
    curl_mime *mime = curl_mime_init(curl);
    curl_mimepart *part;

    // 이메일 본문 추가
    part = curl_mime_addpart(mime);
    curl_mime_data(part, body.c_str(), CURL_ZERO_TERMINATED);
    curl_mime_type(part, "text/plain");

    // 첨부파일 추가
    part = curl_mime_addpart(mime);
    curl_mime_filedata(part, logFilePath.c_str());
    curl_mime_type(part, "application/octet-stream");
    curl_mime_encoder(part, "base64");
    curl_mime_filename(part, logFilePath.substr(logFilePath.find_last_of("/") + 1).c_str());

    // curl 옵션 설정
    curl_easy_setopt(curl, CURLOPT_URL, m_strSmtpServer.c_str());
    curl_easy_setopt(curl, CURLOPT_PORT, m_nSmtpPort);
    curl_easy_setopt(curl, CURLOPT_USERNAME, m_strSenderEmail.c_str());
    curl_easy_setopt(curl, CURLOPT_PASSWORD, emailPassword.c_str());
    curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
    curl_easy_setopt(curl, CURLOPT_MAIL_FROM, ("<" + m_strSenderEmail + ">").c_str());
    curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);    

    return mime;
}

// 메일 보내는 함수
int EmailSender::SendEmailWithAttachment() {
    // 암호화된 비밀번호 복호화해서 가져오기
    std::string emailPassword = GetEmailPassword();
    if (emailPassword.empty()) {
        PrintError("Failed to retrieve email password.");
        return ERROR_CANNOT_SEND_EMAIL;
    }

    // 수신자가 원하는 날짜 받기
    std::string date;
    std::cout << "Enter the date for the log file (YYMMDD): ";
    std::getline(std::cin, date);

    const std::string logFilePath = LOG_SAVE_PATH + date + ".log";
    FILE *logFile = fopen(logFilePath.c_str(), "rb");
    if (!logFile) {
        HandleError(ERROR_CANNOT_OPEN_FILE, logFilePath);
    }

    // curl 초기화
    InitializeCurl();

    // 메일 제목과 내용 설정
    std::string subject = "Log File for " + date;
    std::string body =  "This email contains the log file for " + date + " as attachment.";

    std::string logFileName = logFilePath.substr(logFilePath.find_last_of("/") + 1);

    // 수신자 수신자 및 헤더 설정
    struct curl_slist* recipients = NULL;
    recipients = curl_slist_append(recipients, m_strEmailAddress.c_str());

    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, ("To: " + m_strEmailAddress).c_str());
    headers = curl_slist_append(headers, ("From: " + m_strSenderEmail  + " <" +m_strSenderEmail  + ">").c_str());
    headers = curl_slist_append(headers, ("Subject: " + subject).c_str());

    // MIME 메시지 생성 및 curl 옵션 설정
    curl_mime* mime = SetupMimeAndCurl(m_curl, emailPassword, body, logFilePath, recipients, headers);

    // 이메일 전송
    CURLcode res = curl_easy_perform(m_curl);

    // 리소스 정리
    curl_mime_free(mime);
    curl_slist_free_all(recipients);
    curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        HandleError(ERROR_CANNOT_SEND_EMAIL, "Failed to send email: " + std::string(curl_easy_strerror(res)));
    }

    return SUCCESS_CODE;
}