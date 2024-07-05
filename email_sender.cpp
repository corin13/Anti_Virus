#include <stdexcept>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <jsoncpp/json/json.h>
#include <fstream>
#include "ini.h"
#include "secure_config.h"
#include "util.h"
#include "log_parser.h"
#include "event_monitor.h"
#include "email_sender.h"
#include "aes.h"
#include "crypto_utils.h"

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
    std::vector<unsigned char> key = CCryptoUtils::GetOrGenerateKey(keyFilePath, 32);
    
    std::ifstream timeFile(timeFilePath, std::ios::binary);
    if (timeFile.is_open()) {
        std::vector<unsigned char> encryptedData((std::istreambuf_iterator<char>(timeFile)), std::istreambuf_iterator<char>());
        timeFile.close();

        try {
            std::string decryptedData = CAES::DecryptData(encryptedData, key);
            std::string storedHash = CCryptoUtils::LoadHashFromFile(timeFilePath + ".hash");

            if (!CCryptoUtils::VerifyHash(decryptedData, storedHash)) {
                throw std::runtime_error("Hash verification failed.");
            }

            int64_t d;
            std::istringstream iss(decryptedData);
            iss >> d;

            if (iss.fail() || d < 0) {
                lastEmailSentTime = std::chrono::time_point<std::chrono::steady_clock>::min();
            } else {
                lastEmailSentTime = std::chrono::time_point<std::chrono::steady_clock>(std::chrono::steady_clock::duration(d));
            }
        } catch (const std::exception &e) {
            std::cerr << "Decryption or hash verification failed: " << e.what() << "\n";
            lastEmailSentTime = std::chrono::time_point<std::chrono::steady_clock>::min();
        }
    } else {
        lastEmailSentTime = std::chrono::time_point<std::chrono::steady_clock>::min();
    }
}

void EmailSender::SaveLastEmailSentTime() {
    std::vector<unsigned char> key = CCryptoUtils::GetOrGenerateKey(keyFilePath, 32);

    std::ostringstream oss;
    oss << lastEmailSentTime.time_since_epoch().count();
    std::string plainText = oss.str();

    std::vector<unsigned char> encryptedData = CAES::EncryptData(plainText, key);
    std::string hash = CCryptoUtils::GenerateHash(plainText);

    std::ofstream timeFile(timeFilePath, std::ios::binary);
    if (timeFile.is_open()) {
        timeFile.write(reinterpret_cast<const char*>(encryptedData.data()), encryptedData.size());
        timeFile.close();
    }

    CCryptoUtils::SaveHashToFile(hash, timeFilePath + ".hash");
}

std::string EmailSender::GetFirewallLogFilePath(const std::string& date) const {
    return FIREWALL_LOG_FILE_PATH + date + ".log";
}

void EmailSender::SendLogEmail(){
    std::cout << "\nPlease select the log type you'd like to send:\n\n"
       << "1. File Event Log (Default)\n"
       << "2. Firewall Log\n"
       << "3. Packet Log\n\n"
       << "Please enter the option: ";
    
    std::string logTypeInput;
    int logTypeOption = 1;
    while (true) {
        getline(std::cin, logTypeInput);
        if(logTypeInput == "1" || logTypeInput == "2"|| logTypeInput=="3") {
            logTypeOption = std::stoi(logTypeInput);
            break;
        } else if(logTypeInput.empty()) {
            break;
        }
        std::cout << "Invalid option. Please try again: ";
    }
    std::string logFilePath;
    std::string emailBody;
    std::string subject;
    LogParser logParser;

    switch (logTypeOption) {
        case 1: {
            CEventMonitor eventMonitor;
            logFilePath = eventMonitor.getLogFilePath(); 
            auto logData = logParser.ParseJsonLogFile(logFilePath);

            auto currentTime = std::time(nullptr);
            std::stringstream ss;
            ss << std::put_time(std::localtime(&currentTime), "%Y-%m-%d");

            emailBody = "<html><head><style>"
                        "table {width: 100%; border-collapse: collapse;}"
                        "th, td {border: 1px solid black; padding: 8px; text-align: left;}"
                        "th {background-color: #f2f2f2;}"
                        "</style></head><body>"
                        "<h2>[파일 이벤트의 로그 기록]</h2>"
                        "<p>안녕하세요,</p>"
                        "<p>다음은 " + ss.str() + " 파일 이벤트의 로그 기록입니다:</p>"
                        "<table>"
                        "<tr><th>파일 경로</th><th>시간</th><th>이벤트 타입</th><th>파일 크기</th><th>해시 값 (new)</th><th>해시 값 (old)</th><th>PID</th><th>사용자</th></tr>";

            for (const auto& entry : logData) {
                emailBody += "<tr>"
                             "<td>" + entry.at("target_file") + "</td>"
                             "<td>" + entry.at("timestamp") + "</td>"
                             "<td>" + entry.at("event_type") + "</td>"
                             "<td>" + entry.at("file_size") + " bytes</td>"
                             "<td>" + entry.at("new_hash") + "</td>"
                             "<td>" + entry.at("old_hash") + "</td>"
                             "<td>" + entry.at("pid") + "</td>"
                             "<td>" + entry.at("user") + "</td>"
                             "</tr>";
            }

            emailBody += "</table>"
                         "<p>[연락처 정보]</p>"
                         "<p>시스템 관리자: 이름 (이메일, 전화번호)</p>"
                         "<p>감사합니다.</p>"
                         "<p>우당탕 쿠당탕 드림</p>"
                         "</body></html>";

            subject = "파일 이벤트의 로그 기록";
            break;
        }
        case 2:{
            std::cout << "Enter the date of the log file (e.g., 240101): ";
            std::string date;
            getline(std::cin, date);
            logFilePath = GetFirewallLogFilePath(date);
            auto logData = logParser.ParseFirewallLog(logFilePath);

            emailBody = "<html><body>"
                        "<h2>[Alert] 일간 방화벽 로그 요약 보고서</h2>"
                        "<p>안녕하세요,</p>"
                        "<p>아래는 하루 동안의 방화벽 로그 요약 보고서 입니다.</p>"
                        "<table border='1' cellpadding='5' cellspacing='0'>"
                        "<tr><th>날짜</th><td>" + logData["날짜"] + "</td></tr>"
                        "<tr><th>총 이벤트 수</th><td>" + logData["총 이벤트 수"] + "</td></tr>"
                        "<tr><th>허용된 트래픽</th><td>" + logData["허용된 트래픽"] + "건</td></tr>"
                        "<tr><th>차단된 트래픽</th><td>" + logData["차단된 트래픽"] + "건</td></tr>"
                        "</table>"
                         "<h3>세부 로그</h3>"
                        "<table border='1' cellpadding='5' cellspacing='0'>"
                        "<tr><th>Time</th><th>Hostname</th><th>Action</th><th>Details</th></tr>"
                        + logData["entries"] +
                        "</table>"
                        "<p>[연락처 정보]</p>"
                        "<p>시스템 관리자: 이름 (이메일, 전화번호)</p>"
                        "<p>감사합니다.</p>"
                        "</body></html>";

            subject = "일간 방화벽 로그 요약 보고서";
            break;
        }
        
        case 3:{
            std::cout << "Enter the date of the log file (e.g., 240101): ";
            std::string date;
            getline(std::cin, date);

            // 230719 -> 2023-07-19 형식으로 변환
            std::string year = "20" + date.substr(0, 2);
            std::string month = date.substr(2, 2);
            std::string day = date.substr(4, 2);
            std::string formattedDate = year + "-" + month + "-" + day;

            auto logData = logParser.ParsePacketLogFile(PACKET_LOG_FILE_PATH, formattedDate);

            emailBody = "<html><body>"
                        "<h2>[네트워크 이상 패킷 탐지 알림]</h2>"
                        "<p>안녕하세요,</p>"
                        "<p>네트워크에서 악성 패킷이 탐지되어 알림 드립니다.</p>"
                        "<p>탐지 시스템: Server1</p>"
                        "<h3>탐지된 이상 패킷 정보</h3>"
                        "<table border='1' cellpadding='5' cellspacing='0'>"
                        "<tr><th>타임스탬프</th><th>유형</th><th>내용</th></tr>";

            // 로그 항목이 제대로 파싱되었는지 확인하기 위해 디버그 출력
            if (logData.find(formattedDate) != logData.end()) {
                for (const auto& entry : logData[formattedDate]) {
                    std::istringstream logStream(entry);
                    std::string line;
                    std::string timestamp;
                    std::string type;
                    std::string content;

                    // 로그 항목의 각 줄을 파싱하여 변환
                    while (std::getline(logStream, line)) {
                        if (line.find("[info]") != std::string::npos) {
                            timestamp = line;
                        } else if (line.find("IP Flooding detected in") != std::string::npos) {
                            type = "IP 플러딩";
                            content = "감지된 IP: " + line.substr(line.find("in ") + 3);
                        } else if (line.find("Malicious packet detected:") != std::string::npos) {
                            type = "악성 패킷";
                            content = "감지된 패킷: " + line.substr(line.find("detected: ") + 10);
                        } else if (line.find("Reason:") != std::string::npos) {
                            content += "탐지된 이상 유형: " + line.substr(line.find("Reason: ") + 8);
                        } else if (line.find("Large packet detected in") != std::string::npos) {
                            type = "대형 패킷";
                            content = "감지된 패킷: " + line.substr(line.find("in ") + 3);
                        } else if (line.find("Packet fragmentation detected:") != std::string::npos) {
                            type = "패킷 분할";
                            content = "감지된 패킷: " + line.substr(line.find("detected: ") + 10);
                        } else if (line.find("Malicious payload detected in") != std::string::npos) {
                            type = "악성 페이로드";
                            content = "감지된 페이로드: " + line.substr(line.find("in ") + 3);
                        }
                    }

                    emailBody += "<tr><td>" + timestamp + "</td><td>" + type + "</td><td>" + content + "</td></tr>";
                }
            } else {
                std::cerr << "No log data found for the given date." << std::endl;
                emailBody += "<tr><td colspan='3'>No log data found for the given date.</td></tr>";
            }

            emailBody += "</table>"
                         "<p>[연락처 정보]</p>"
                         "<p>시스템 관리자: 이름 (이메일, 전화번호)</p>"
                         "<p>감사합니다.</p>"
                         "</body></html>";

            subject = "네트워크 이상 패킷 탐지 알림";
            logFilePath = PACKET_LOG_FILE_PATH;  // logFilePath 설정
            break;
        }
        default:
            return;
    }
    if (SendEmailWithAttachment(subject, emailBody, logFilePath) == 0) {
        //
    } else {
        std::cerr << "Failed to send email.\n";
    }
}