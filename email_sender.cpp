#include <cstdlib>
#include <string>
#include <fstream>
#include <iostream>
#include "email_sender.h"
#include "event_monitor.h"
#include "util.h"

EmailSender::EmailSender(const std::string& smtpServer, int smtpPort, const std::string& emailAddress)
    : smtpServer(smtpServer), smtpPort(smtpPort), emailAddress(emailAddress) {}

// 환경변수에서 이메일 비밀번호 가져오기
const char* EmailSender::GetEmailPassword() {
    const char* emailPassword = std::getenv("EMAIL_PASSWORD");
    if (!emailPassword) {
        HandleError(ERROR_INVALID_FUNCTION, "Email password is not set in the environment variables.");
    }
    return emailPassword;
}

// curl 초기화
CURL* EmailSender::InitializeCurl() const {
    CURL *curl = curl_easy_init();
    if (!curl) {
        HandleError(ERROR_INVALID_FUNCTION, "Failed to initialize libcurl.");
    }
    return curl;
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
     curl_easy_setopt(curl, CURLOPT_URL, smtpServer.c_str());
    curl_easy_setopt(curl, CURLOPT_PORT, smtpPort);
    curl_easy_setopt(curl, CURLOPT_USERNAME, senderEmail.c_str());
    curl_easy_setopt(curl, CURLOPT_PASSWORD, emailPassword.c_str());
    curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
    curl_easy_setopt(curl, CURLOPT_MAIL_FROM, ("<" + senderEmail + ">").c_str());
    curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);    

    return mime;
}

// 메일 보내는 함수
int EmailSender::SendEmailWithAttachment() {
    // 환경변수에서 이메일 비밀번호 가져오기
    const char* emailPassword = GetEmailPassword();

    // curl 초기화
    CURL *curl = InitializeCurl();

    // 메일 제목과 내용 설정
    std::string subject = "Test Email with Log File";
    std::string body = "This email contains today's log file as attachment.";

    const std::string logFilePath = GetLogFilePath();
    FILE *logFile = fopen(logFilePath.c_str(), "rb");
    if (!logFile) {
        HandleError(ERROR_CANNOT_OPEN_FILE, logFilePath);
    }

    std::string logFileName = logFilePath.substr(logFilePath.find_last_of("/") + 1);

    // 수신자 수신자 및 헤더 설정
    struct curl_slist* recipients = NULL;
    recipients = curl_slist_append(recipients, emailAddress.c_str());

    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, ("To: " + emailAddress).c_str());
    headers = curl_slist_append(headers, ("From: " + senderEmail  + " <" +senderEmail  + ">").c_str());
    headers = curl_slist_append(headers, ("Subject: " + subject).c_str());

    // MIME 메시지 생성 및 curl 옵션 설정
    curl_mime* mime = SetupMimeAndCurl(curl, emailPassword, body, logFilePath, recipients, headers);

    // 이메일 전송
    CURLcode res = curl_easy_perform(curl);

    // 리소스 정리
    curl_mime_free(mime);
    curl_slist_free_all(recipients);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        HandleError(ERROR_CANNOT_SEND_EMAIL, "Failed to send email: " + std::string(curl_easy_strerror(res)));
    }

    return SUCCESS_CODE;
}