#include <arpa/inet.h> 
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstring>
#include <fstream> 
#include <iomanip>
#include <iostream> 
#include <IPv4Layer.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h> 
#include <netinet/udp.h> 
#include <Packet.h>
#include <pcap.h> 
#include <PcapLiveDevice.h>
#include <PcapLiveDeviceList.h>
#include <stdexcept> 
#include <sys/socket.h>
#include <SystemUtils.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include "packet_handler.h"
#include "email_sender.h"
#include "log_parser.h"
#include "config.h"
#include "util.h"

CPacketHandler::CPacketHandler()
    : m_DetectionCount(0), m_NormalPacketCount(0), m_AbnormalPacketCount(0),
      m_DuplicateIPCount(0), m_LargePacketCount(0), m_MaliciousPayloadCount(0), m_MaliciousPacketCount(0),
      vt({"No", "Packet Size", "Random src IP", "IP Flooding", "Fragmentation", "Data"}, COLUMN_WIDTH)
      {}
CPacketHandler::~CPacketHandler() {}

// 공통 패킷 처리 함수
void CPacketHandler::ProcessPacket(CPacketHandler *pHandler, const struct ip* pIpHeader, int nPayloadLength, const u_char* pPayload, const std::string& strSrcIP) {
    pHandler->AnalyzePacket(pIpHeader, pPayload, nPayloadLength, strSrcIP);
}

// pcap 패킷 처리 핸들러 함수
int CPacketHandler::PacketHandler(u_char *pUserData, const struct pcap_pkthdr* pPkthdr, const u_char* pPacket) {
    try {
        CPacketHandler *pHandler = reinterpret_cast<CPacketHandler*>(pUserData);
        const struct ip* pIpHeader = (struct ip*)(pPacket + ETHERNET_HEADER_LENGTH);
        int nIpHeaderLength = pIpHeader->ip_hl * IP_HEADER_LENGTH_UNIT;
        int nIpTotalLength = ntohs(pIpHeader->ip_len);
        int nPayloadLength = nIpTotalLength - nIpHeaderLength;
        const u_char* pPayload = pPacket + ETHERNET_HEADER_LENGTH + nIpHeaderLength;
        std::string strSrcIP = inet_ntoa(pIpHeader->ip_src);

        pHandler->ProcessPacket(pHandler, pIpHeader, nPayloadLength, pPayload, strSrcIP);
        return SUCCESS_CODE;
    } catch (const std::exception& e) {
        std::cerr << "Exception caught in PacketHandler: " << e.what() << std::endl;
        return ERROR_UNKNOWN;
    }
}

std::atomic<uint64_t> totalBytes(0);

// 패킷의 IP 주소, 프로토콜, 크기를 분석하여 악성 패킷을 감지하고 로그 파일에 기록
int CPacketHandler::LogPacket(pcpp::RawPacket* pRawPacket, pcpp::PcapLiveDevice* pDevice, void* pUserCookie) {
    try {
        CPacketHandler *handler = reinterpret_cast<CPacketHandler*>(pUserCookie);
        pcpp::Packet packet(pRawPacket);
        pcpp::IPv4Layer* ipLayer = packet.getLayerOfType<pcpp::IPv4Layer>();

        if (ipLayer != nullptr) {
            std::string srcIP = ipLayer->getSrcIPAddress().toString();
            std::string dstIP = ipLayer->getDstIPAddress().toString();
            int packetLen = packet.getRawPacket()->getRawDataLen();
            int protocol = ipLayer->getIPv4Header()->protocol;

            totalBytes += packetLen;

            const struct ip* pIpHeader = (struct ip*)ipLayer->getData();
            int nPayloadLength = packetLen - (pIpHeader->ip_hl * IP_HEADER_LENGTH_UNIT);
            const u_char* pPayload = (const u_char*)ipLayer->getData() + (pIpHeader->ip_hl * IP_HEADER_LENGTH_UNIT);

            handler->ProcessPacket(handler, pIpHeader, nPayloadLength, pPayload, srcIP);
        }
        return SUCCESS_CODE;
    } catch (const std::exception& e) {
        std::cerr << "Exception caught in LogPacket: " << e.what() << std::endl;
        return ERROR_UNKNOWN;
    }
}

// 대역폭 모니터링 함수
int CPacketHandler::MonitorBandwidth() {
    try {
        auto startTime = std::chrono::steady_clock::now();
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            auto endTime = std::chrono::steady_clock::now();
            std::chrono::duration<double> elapsedSeconds = endTime - startTime;

            uint64_t bytes = totalBytes.exchange(0);
            double dBandwidth = (bytes * BITS_PER_BYTE) / elapsedSeconds.count();

            std::cout << "Current bandwidth: " << dBandwidth << " bps" << std::endl;
            startTime = endTime;
        }
        return SUCCESS_CODE;
    } catch (const std::exception& e) {
        std::cerr << "Exception caught in MonitorBandwidth: " << e.what() << std::endl;
        return ERROR_UNKNOWN;
    }
}

std::atomic<bool> stop_capture(false);

// 프로그램 실행 중 SIGINT 신호를 받았을 때 이를 처리하고 패킷 캡처를 중지하는 함수
void CPacketHandler::SigintHandler(int signum) {
    try {
        std::cout << "Interrupt signal (" << signum << ") received.\n";
        stop_capture = true;
    } catch (const std::exception& e) {
        std::cerr << "Exception caught in SigintHandler: " << e.what() << std::endl;
    }
}

// pcap 파일을 열어 각 패킷을 분석하고 패킷을 탐지하는 함수
int CPacketHandler::AnalyzeNetworkTraffic(const char *pcap_file) {
    try {
        char chErrBuf[PCAP_ERRBUF_SIZE];
        pcap_t *pHandle = pcap_open_offline(pcap_file, chErrBuf);
        if (pHandle == nullptr) {
            std::cerr << "Could not open pcap file: " << chErrBuf << std::endl;
            return ERROR_CANNOT_OPEN_FILE;
        }

        struct pcap_pkthdr *pHeader;
        const u_char *pData;
        int packetCount = 0;
        while (int res = pcap_next_ex(pHandle, &pHeader, &pData) >= 0) {
            if (res == 0) continue;
            PacketHandler(reinterpret_cast<u_char*>(this), pHeader, pData);
            packetCount++;
        }

        pcap_close(pHandle);
        return SUCCESS_CODE;
    } catch (const std::exception& e) {
        std::cerr << "Exception caught in AnalyzeNetworkTraffic: " << e.what() << std::endl;
        return ERROR_UNKNOWN;
    }
}

// 패킷을 분석하여 악성 여부를 판단하고 로그 파일에 기록
int CPacketHandler::AnalyzePacket(const struct ip* pIpHeader, const u_char* pPayload, int nPayloadLength, const std::string& strSrcIP) {
    try{
        bool bIsMalicious = false;
        bool bPayloadMalicious = false;
        bool bIpFloodingDetected = false;
        bool bRandomIPDetected = false;
        bool bLargePacketDetected = false;
        bool bFragmentationDetected = false;
        auto currentTime = std::chrono::steady_clock::now();

        std::ofstream logFile("logs/detailed_logs.log", std::ios_base::app);

        // 비정상 패킷이 정상 패킷보다 같은 시간 동안 2배 이상 많은지 확인
        if (bIsMalicious) {
            m_AbnormalPacketCount++;
        } else {
            m_NormalPacketCount++;
        }

        if (std::chrono::duration_cast<std::chrono::seconds>(currentTime - lastCheckTime).count() >= 60) {
            if (m_AbnormalPacketCount > m_NormalPacketCount * ABNORMAL_PACKET_RATIO) {
                std::string msg = "Abnormal packet count exceeds twice the normal packet count within the same time period.";
                if (strLoggedMessages.find(msg) == strLoggedMessages.end()) {
                    logFile << msg << std::endl;
                    std::cout << msg << std::endl;
                    strLoggedMessages.insert(msg);
                }
            }
            m_NormalPacketCount = 0;
            m_AbnormalPacketCount = 0;
            lastCheckTime = currentTime;
        }

        // 동일 IP 주소에서 과도한 패킷 발생 확인
        std::string floodingIP = "";
        nIpFloodingCount[strSrcIP]++;
        if (nIpFloodingCount[strSrcIP] > FLOODING_THRESHOLD && strProcessedIPs.find(strSrcIP + "-flooding") == strProcessedIPs.end()) {
            std::string strMsg = "IP Flooding detected in " + strSrcIP;
            m_DuplicateIPCount++;
            logFile << strMsg << std::endl;
            strLoggedMessages.insert(strMsg);
            strProcessedIPs.insert(strSrcIP + "-flooding");
            bIsMalicious = true;
            bIpFloodingDetected = true;
            floodingIP = strSrcIP;
        }

        // 출발지 IP 주소를 해당 페이로드에 대한 집합에 추가
        std::string strPayloadString(reinterpret_cast<const char*>(pPayload), nPayloadLength);
        strIpAddressesForPayload[strPayloadString].insert(strSrcIP);

        // 동일한 페이로드에 대해 출발지 IP 주소가 임계값 이상일 경우 무작위 출발지 IP로 간주
        if (strIpAddressesForPayload[strPayloadString].size() > RANDOM_IP_THRESHOLD) {
            std::cout << "Random source IP detected for payload: " << strPayloadString << std::endl;
            bRandomIPDetected = true;
            bIsMalicious = true;
        }

        if (bRandomIPDetected) {
            std::cout << "Detected random IPs:" << std::endl;
            for (const auto& ip : strIpAddressesForPayload[strPayloadString]) {
                std::cout << ip << std::endl;
            }
        }

        // 페이로드의 80% 이상이 'A'로 채워져 있을 경우 악성으로 간주
        int nCount = std::count(pPayload, pPayload + nPayloadLength, 'A');
        if (nCount >= 0.8 * nPayloadLength) bPayloadMalicious = true;

        if (bPayloadMalicious && strProcessedIPs.find(strSrcIP + "-payload") == strProcessedIPs.end()) {
            std::string strMsg = "Malicious payload detected in " + strSrcIP;
            strUniqueMaliciousIPs.insert(strSrcIP);
            m_MaliciousPayloadCount++;
            logFile << strMsg << std::endl;
            strLoggedMessages.insert(strMsg);
            strProcessedIPs.insert(strSrcIP + "-payload");
            bIsMalicious = true;
        }

        // 큰 패킷 확인 및 동일한 크기의 패킷으로 구성
        int nIpLength = ntohs(pIpHeader->ip_len);
        static int nPreviousPacketLength = -1;
        if (nPreviousPacketLength == -1) {
            nPreviousPacketLength = nIpLength;
        } else if (nPreviousPacketLength != nIpLength) {
            bLargePacketDetected = false;
        } else {
            bLargePacketDetected = true;
        }
        if (nIpLength > MAX_PACKET_SIZE && strProcessedIPs.find(strSrcIP + "-largePacket") == strProcessedIPs.end()) {
            std::string strMsg = "Large packet detected in " + strSrcIP + ": " + std::to_string(nIpLength) + " bytes";
            m_LargePacketCount++;
            strUniqueLargeIPs.insert(strSrcIP);
            nLargePacketSizes.insert(nIpLength);
            logFile << strMsg << std::endl;
            strLoggedMessages.insert(strMsg);
            strProcessedIPs.insert(strSrcIP + "-largePacket");
            bIsMalicious = true;
        }
        nPreviousPacketLength = nIpLength;

        // 패킷 단편화 확인
        int nIpOffset = ntohs(pIpHeader->ip_off);
        if ((nIpOffset & IP_MF || (nIpOffset & IP_OFFMASK) != 0) && pIpHeader->ip_p != IPPROTO_TCP && nIpLength > MTU_SIZE && strProcessedIPs.find(strSrcIP + "-fragmentation") == strProcessedIPs.end()) {
            std::string strMsg = "Packet fragmentation detected: " + strSrcIP;
            logFile << strMsg << std::endl;
            strLoggedMessages.insert(strMsg);
            strProcessedIPs.insert(strSrcIP + "-fragmentation");
            bIsMalicious = true;
            bFragmentationDetected = true;
        }

        if (bIsMalicious && strProcessedIPs.find(strSrcIP) == strProcessedIPs.end()) {
            m_MaliciousPacketCount++;
            if (strLoggedIPs.find(strSrcIP) == strLoggedIPs.end()) {
                std::ofstream outfile;
                outfile.open("logs/malicious_ips.log", std::ios_base::app);
                if (!outfile.is_open()) return ERROR_CANNOT_OPEN_FILE;
                
                outfile << strSrcIP << std::endl;
                outfile.close();
                strLoggedIPs.insert(strSrcIP);
            }

            // 탐지된 패킷 정보를 표에 추가
            m_DetectionCount++;
            std::string strDetectedRandomIP = bRandomIPDetected ? std::to_string(strIpAddressesForPayload[strPayloadString].size()) + " different IPs" : "No";
            int nCount = std::count(pPayload, pPayload + nPayloadLength, 'A');
            std::string strDisplayFloodingIP = !floodingIP.empty() ? floodingIP : "No";

            vt.addRow(
                std::to_string(m_DetectionCount),
                std::to_string(nIpLength) + " bytes",
                strDetectedRandomIP,
                strDisplayFloodingIP,
                bFragmentationDetected ? "Yes" : "No",
                bPayloadMalicious ? std::to_string(nCount) + " bytes" : "No"
            );

            logFile << "Malicious packet detected: " << strSrcIP << std::endl;
            if (bPayloadMalicious) logFile << "- Reason: Malicious payload" << std::endl;
            if (bIpFloodingDetected) logFile << "- Reason: IP Flooding" << std::endl;
            if (bRandomIPDetected) logFile << "- Reason: Random source IP" << std::endl;
            if (bLargePacketDetected) logFile << "- Reason: Large packet" << std::endl;
            if (bFragmentationDetected) logFile << "- Reason: Packet fragmentation" << std::endl;

            strProcessedIPs.insert(strSrcIP);
        }

        logFile.close();
        return SUCCESS_CODE;
    } catch (const std::exception& e) {
        std::cerr << "Exception caught in AnalyzePacket: " << e.what() << std::endl;
        return ERROR_UNKNOWN;
    }
}

// 전역적으로 원래 버퍼를 저장할 변수
std::streambuf* CPacketHandler::originalCoutBuffer = nullptr;

// 출력을 비활성화하는 함수
void CPacketHandler::DisableOutput() {
    try {
        CPacketHandler::originalCoutBuffer = std::cout.rdbuf();
        std::cout.rdbuf(nullptr);
    } catch (const std::exception& e) {
        std::cerr << "Exception caught in DisableOutput: " << e.what() << std::endl;
    }
}

// 출력을 다시 활성화하는 함수
void CPacketHandler::EnableOutput() {
    try {
        std::cout.rdbuf(CPacketHandler::originalCoutBuffer);
    } catch (const std::exception& e) {
        std::cerr << "Exception caught in EnableOutput: " << e.what() << std::endl;
    }
}

// 네트워크 인터페이스에서 패킷을 생성, 캡처 및 분석하는 시스템을 실행하는 함수
int CPacketHandler::RunSystem(const char* pInterfaceName) {
    try{
        auto dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(pInterfaceName);
        if (!dev) {
            std::cerr << "Cannot find interface: " << pInterfaceName << std::endl;
            return ERROR_CANNOT_FIND_INTERFACE;
        }

        if (!dev->open()) {
            std::cerr << "Cannot open device: " << pInterfaceName << std::endl;
            return ERROR_CANNOT_OPEN_DEVICE;
        }

        CPacketGenerator packetGenerator;
        std::atomic<int> totalMaliciousPacketsSent(0);
        std::thread packetThread([&]() {
            packetGenerator.GenerateMaliciousPackets(totalMaliciousPacketsSent);
        });
        packetThread.join();

        CPacketHandler handler;
        if (handler.PromptUserForPacketCapture()) {
            handler.CapturePackets(pInterfaceName);
            if (handler.PromptUserForPacketAnalysis()) {
                handler.AnalyzeCapturedPackets();
            }
        } else {
            std::cout << "No packets captured." << std::endl;
        } 
        return SUCCESS_CODE;
    } catch (const std::exception& e) {
        std::cerr << "Exception caught in RunSystem: " << e.what() << std::endl;
        return ERROR_UNKNOWN;
    }
}

// 사용자에게 패킷 캡처를 시작할지 여부를 묻고 그 결과를 반환하는 함수
bool CPacketHandler::PromptUserForPacketCapture() {
    try {
        char chUserInput;
        std::cout << COLOR_WHITE "\n## Do you want to capture the sent packets? (y/n): " << COLOR_RESET;
        std::cin >> chUserInput;
        return chUserInput == 'y' || chUserInput == 'Y';
    } catch (const std::exception& e) {
        std::cerr << "Exception caught in PromptUserForPacketCapture: " << e.what() << std::endl;
        return false;
    }
}

// 사용자에게 패킷을 분석할지 여부를 묻고 그 결과를 반환하는 함수
bool CPacketHandler::PromptUserForPacketAnalysis() {
    try {
        char chUserInput;
        sleep(1);
        std::cout << COLOR_WHITE "## Do you want to analyze malicious packets among the captured packets? (y/n): " << COLOR_RESET;
        std::cin >> chUserInput;
        return chUserInput == 'y' || chUserInput == 'Y';
    } catch (const std::exception& e) {
        std::cerr << "Exception caught in PromptUserForPacketAnalysis: " << e.what() << std::endl;
        return false;
    }
}

// 네트워크 인터페이스에서 패킷을 캡처하고 'captured_packets.pcap' 파일에 저장하는 함수
int CPacketHandler::CapturePackets(const char* pInterfaceName) {
    try{
        std::cout << COLOR_GREEN "Capturing packets on " << pInterfaceName << "... Press Ctrl+C to stop\n" << COLOR_RESET << std::endl;

        char chErrBuf[PCAP_ERRBUF_SIZE];
        auto pcapHandle = pcap_open_live(pInterfaceName, MAX_SNAP_LEN, 1, 10, chErrBuf);
        if (!pcapHandle) {
            std::cerr << "Couldn't open device " << pInterfaceName << ": " << chErrBuf << std::endl;
            return ERROR_CANNOT_OPEN_DEVICE;
        }

        auto pcapDumper = pcap_dump_open(pcapHandle, "captured_packets.pcap");
        if (!pcapDumper) {
            std::cerr << "Couldn't open output file: " << pcap_geterr(pcapHandle) << std::endl;
            return ERROR_CANNOT_OPEN_FILE;
        }

        signal(SIGINT, CPacketHandler::SigintHandler);

        auto pcapCallback = [](u_char* pUserData, const struct pcap_pkthdr* pPkthdr, const u_char* pPacket) {
            pcap_dump(pUserData, pPkthdr, pPacket);
        };

        while (!stop_capture) {
            pcap_dispatch(pcapHandle, 0, pcapCallback, (u_char*)pcapDumper);
        }
        pcap_dump_close(pcapDumper);
        pcap_close(pcapHandle);

        std::cout << "Packets captured and saved to " << COLOR_YELLOW << "'captured_packets.pcap'." << COLOR_RESET << "\n" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Exception caught in CapturePackets: " << e.what() << std::endl;
        return ERROR_CANNOT_CAPTURE_PACKETS;
    }
    return SUCCESS_CODE;
}

// 캡처된 패킷 파일을 분석한 결과를 표 형태로 출력하며, 필요한 경우 IP를 차단하고 로그 파일을 이메일로 전송하는 함수
int CPacketHandler::AnalyzeCapturedPackets() {
    try{
        auto result = AnalyzeNetworkTraffic("captured_packets.pcap");
        if (result == SUCCESS_CODE) {
            std::cout << COLOR_GREEN "Packet analysis completed successfully." << COLOR_RESET << std::endl;
        } else {
            std::cerr << "Packet analysis failed with error code: " << result << std::endl;
        }

        std::cout << COLOR_RED;
        vt.print(std::cout);
        std::cout << COLOR_RESET;

        if (PromptUserForBlockingIPs()) BlockDetectedIPs();

        SendEmailWithLogPacketData(LOG_FILE_PATH);
    } catch (const std::exception& e) {
        std::cerr << "Exception caught in AnalyzeCapturedPackets: " << e.what() << std::endl;
        return ERROR_CANNOT_ANALYZE_PACKETS;
    }
    return SUCCESS_CODE;
}

// 사용자에게 탐지된 IP를 차단할지 여부를 묻고 그 결과를 반환하는 함수
bool CPacketHandler::PromptUserForBlockingIPs() {
    try{
        char chUserInput;
        sleep(1);

        std::cout << COLOR_RED "\n## Do you want to block the detected malicious IPs? (y/n): " << COLOR_RESET;
        std::cin >> chUserInput;
        if (chUserInput == 'y' || chUserInput == 'Y') {
            return true;
        } else {
            std::cout << "No IPs blocked." << std::endl;
            return false;
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception caught in PromptUserForBlockingIPs: " << e.what() << std::endl;
        return ERROR_CANNOT_PROMPT_USER;
    }
}

// 로그파일에서 탐지된 이상 IP를 읽어와 해당 IP를 차단하는 iptables 명령을 실행하는 함수
int CPacketHandler::BlockDetectedIPs() {
    try{
        std::ifstream infile("logs/malicious_ips.log");
        if (!infile.is_open()) {
            std::cerr << "Could not open malicious_ips.log for reading." << std::endl;
            return ERROR_CANNOT_OPEN_FILE;
        }

        Firewall firewall;
        std::string strIp;
        while (std::getline(infile, strIp)) {
            DisableOutput();
            int nSshInputResult = firewall.RunIptables("INPUT", strIp, "22", "ACCEPT");
            int nSshOutputResult = firewall.RunIptables("OUTPUT", strIp, "22", "ACCEPT");
            EnableOutput();
            if (nSshInputResult != SUCCESS_CODE || nSshOutputResult != SUCCESS_CODE) {
                std::cerr << "Failed to set SSH exception for IP " << strIp << "." << std::endl;
                continue;
            }
            int result = firewall.RunIptables("INPUT", strIp, "80", "DROP");
            if (result == SUCCESS_CODE) {
                std::cout << "IP " << strIp << " has been blocked successfully.\n" << std::endl;
            } else {
                std::cerr << "Failed to block IP " << strIp << "." << std::endl;
            }
        }

        infile.close();
    } catch (const std::exception& e) {
        std::cerr << "Exception caught in BlockDetectedIPs: " << e.what() << std::endl;
        return ERROR_CANNOT_BLOCK_IP;
    }
    return SUCCESS_CODE;
}

// 로그 파일에서 특정 정보를 파싱하여 이메일을 작성하고, 이메일을 전송하는 함수
void CPacketHandler::SendEmailWithLogPacketData(const std::string& logFilePath) {
    LogParser logParser;
    std::vector<std::string> strKeys = {
        "악성 패킷 출발지 IP", "출발지 IP 주소", "탐지된 이상 유형"
    };
    auto logData = logParser.ParseLogFile(logFilePath, strKeys);

    std::string emailBody =
        "[네트워크 이상 패킷 탐지 알림]\n\n"
        "안녕하세요,\n"
        "네트워크에서 악성 패킷이 탐지되어 알림 드립니다.\n\n"
        "탐지 시스템: Server1\n\n"
        "[탐지된 이상 패킷 정보]\n"
        "출발지 IP 주소: " + logData["출발지 IP 주소"] + "\n"
        "악성 IP 주소: " + logData["악성 패킷 출발지 IP"] + "\n"
    
        "탐지된 이상 유형: " + logData["탐지된 이상 유형"] + "\n\n"
        "[추가 정보]\n"
        "탐지된 패킷 내용: (필요 시 여기에 추가)\n"
        "연관된 규칙: Rule-ID-12345 (DDoS 탐지 규칙)\n\n"
        "[조치 권고 사항]\n"
        "즉각적인 조치: 출발지 IP " + logData["출발지 IP 주소"] + "을 차단\n"
        "추가 조사: 출발지 IP의 이전 트래픽 패턴 분석 등\n\n"
        "[연락처 정보]\n"
        "시스템 관리자: 이름 (이메일, 전화번호)\n\n"
        "감사합니다.\n"
        "~~드림";

    std::string subject = "네트워크 이상 패킷 탐지 알림";

    std::string recipientEmailAddress = Config::Instance().GetEmailAddress();
    if (!recipientEmailAddress.empty()) {
        EmailSender emailSender("smtps://smtp.gmail.com", 465, recipientEmailAddress);
        if (emailSender.SendEmailWithAttachment(subject, emailBody, logFilePath) == 0) {
            std::cout << "\n" << COLOR_GREEN << "Email sent successfully." << COLOR_RESET << "\n";
        } else {
            HandleError(ERROR_CANNOT_SEND_EMAIL);
        }
    } else {
        std::cerr << "Email address is not configured.\n";
    }
}