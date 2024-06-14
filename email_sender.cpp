#include "email_sender.h"
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <jsoncpp/json/json.h>
#include <fstream>
#include "ini.h"
#include "secure_config.h"
#include "util.h"

EmailSender::EmailSender(const std::string& smtpServer, int smtpPort, const std::string& emailAddress)
    : m_strSmtpServer(smtpServer), m_nSmtpPort(smtpPort), m_strEmailAddress(emailAddress), m_curl(nullptr) {
    m_strSenderEmail = GetSenderEmail();
    LoadLastEmailSentTime(); // 마지막 이메일 전송 시간 로드
}

EmailSender::~EmailSender() {
    if (m_curl) {
        curl_easy_cleanup(m_curl);
    }
}

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

std::string EmailSender::GetSenderEmail() {
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
        std::string decrypted_email = ISecurityconfig.getDecryptedEmail(KEY_SECURITY, "encrypted_email");
        return decrypted_email;
    } catch (const std::exception& e) {
        PrintError(e.what());
        return "";
    }
}

void EmailSender::InitializeCurl() {
    m_curl = curl_easy_init();
    if (!m_curl) {
        HandleError(ERROR_INVALID_FUNCTION, "Failed to initialize libcurl.");
    }
}

curl_mime* EmailSender::SetupMimeAndCurl(CURL* curl, const std::string& emailPassword, const std::string& subject, const std::string& body, const std::string& logFilePath, curl_slist* recipients, curl_slist* headers) const {
    curl_mime *mime = curl_mime_init(curl);
    curl_mimepart *part;

    part = curl_mime_addpart(mime);
    curl_mime_data(part, body.c_str(), CURL_ZERO_TERMINATED);
    curl_mime_type(part, "text/html");
    curl_mime_name(part, "body");

    part = curl_mime_addpart(mime);
    curl_mime_filedata(part, logFilePath.c_str());
    curl_mime_type(part, "application/octet-stream");
    curl_mime_encoder(part, "base64");
    curl_mime_filename(part, logFilePath.substr(logFilePath.find_last_of("/") + 1).c_str());

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

int EmailSender::SendEmailWithAttachment(const std::string& subject, const std::string& body, const std::string& logFilePath) {
    auto now = std::chrono::steady_clock::now();

    if (lastEmailSentTime.time_since_epoch().count() > 0) {  // Check if the email has been sent at least once
        auto timeSinceLastEmail = std::chrono::duration_cast<std::chrono::minutes>(now - lastEmailSentTime);
        if (timeSinceLastEmail < emailInterval) {
            auto minutesLeft = emailInterval - timeSinceLastEmail;
            std::cerr << "You must wait " << minutesLeft.count() << " more minutes before sending another email." << std::endl;
            return ERROR_CANNOT_SEND_EMAIL;
        }
    }

    std::string emailPassword = GetEmailPassword();
    if (emailPassword.empty()) {
        PrintError("Failed to retrieve email password.");
        return ERROR_CANNOT_SEND_EMAIL;
    }

    FILE *logFile = fopen(logFilePath.c_str(), "rb");
    if (!logFile) {
        HandleError(ERROR_CANNOT_OPEN_FILE, logFilePath);
        return ERROR_CANNOT_OPEN_FILE;
    }
    fclose(logFile);

    InitializeCurl();

    std::string logFileName = logFilePath.substr(logFilePath.find_last_of("/") + 1);

    struct curl_slist* recipients = NULL;
    recipients = curl_slist_append(recipients, m_strEmailAddress.c_str());

    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, ("To: " + m_strEmailAddress).c_str());
    headers = curl_slist_append(headers, ("From: " + m_strSenderEmail  + " <" + m_strSenderEmail  + ">").c_str());
    headers = curl_slist_append(headers, ("Subject: " + subject).c_str());

    curl_mime* mime = SetupMimeAndCurl(m_curl, emailPassword, subject, body, logFilePath, recipients, headers);

    CURLcode res = curl_easy_perform(m_curl);

    curl_mime_free(mime);
    curl_slist_free_all(recipients);
    curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        HandleError(ERROR_CANNOT_SEND_EMAIL, "Failed to send email: " + std::string(curl_easy_strerror(res)));
        return ERROR_CANNOT_SEND_EMAIL;
    }

    lastEmailSentTime = now;
    SaveLastEmailSentTime(); // 마지막 이메일 전송 시간 저장
    std::cout << "Email sent successfully." << std::endl;
    return SUCCESS_CODE;
}

void EmailSender::LoadLastEmailSentTime() {
    std::ifstream timeFile(timeFilePath);
    if (timeFile.is_open()) {
        int64_t d;
        timeFile >> d;
        lastEmailSentTime = std::chrono::time_point<std::chrono::steady_clock>(std::chrono::steady_clock::duration(d));
        timeFile.close();
    } else {
        lastEmailSentTime = std::chrono::time_point<std::chrono::steady_clock>::min();
    }
}

void EmailSender::SaveLastEmailSentTime() {
    std::ofstream timeFile(timeFilePath);
    if (timeFile.is_open()) {
        timeFile << lastEmailSentTime.time_since_epoch().count();
        timeFile.close();
    }
}
