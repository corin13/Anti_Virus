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

CPacketHandler::CPacketHandler()
    : m_DuplicateIPCount(0), m_LargePacketCount(0), m_MaliciousPayloadCount(0), m_MaliciousPacketCount(0),
      vt({"No", "Packet Size", "Random src IP", "IP Flooding", "Fragmentation", "Data"}, COLUMN_WIDTH) {}

CPacketHandler::~CPacketHandler() {}

// 공통 패킷 처리 함수
void CPacketHandler::ProcessPacket(CPacketHandler *pHandler, const struct ip* pIpHeader, int nPayloadLength, const u_char* pPayload, const std::string& srcIP) {
    pHandler->AnalyzePacket(pIpHeader, pPayload, nPayloadLength, srcIP);
}

// pcap 패킷 처리 핸들러 함수
void CPacketHandler::PacketHandler(u_char *pUserData, const struct pcap_pkthdr* pPkthdr, const u_char* pPacket) {
    CPacketHandler *pHandler = reinterpret_cast<CPacketHandler*>(pUserData); 
    const struct ip* pIpHeader = (struct ip*)(pPacket + ETHERNET_HEADER_LENGTH); 
    int nIpHeaderLength = pIpHeader->ip_hl * IP_HEADER_LENGTH_UNIT; 
    int nIpTotalLength = ntohs(pIpHeader->ip_len); 
    int nPayloadLength = nIpTotalLength - nIpHeaderLength;
    const u_char* pPayload = pPacket + ETHERNET_HEADER_LENGTH + nIpHeaderLength; 
    std::string strSrcIP = inet_ntoa(pIpHeader->ip_src); 

    pHandler->ProcessPacket(pHandler, pIpHeader, nPayloadLength, pPayload, strSrcIP); 
}

std::atomic<uint64_t> totalBytes(0);  

// 패킷의 IP 주소, 프로토콜, 크기를 분석하여 악성 패킷을 감지하고 로그 파일에 기록
void CPacketHandler::LogPacket(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* dev, void* userCookie) {
    CPacketHandler *handler = reinterpret_cast<CPacketHandler*>(userCookie);
    pcpp::Packet packet(rawPacket);
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
}

// 대역폭 모니터링 함수
void CPacketHandler::MonitorBandwidth() {
    auto startTime = std::chrono::steady_clock::now();
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        auto endTime = std::chrono::steady_clock::now();
        std::chrono::duration<double> elapsedSeconds = endTime - startTime;
        
        uint64_t bytes = totalBytes.exchange(0);
        double bandwidth = (bytes * BITS_PER_BYTE) / elapsedSeconds.count();  // 대역폭(bps) 계산
        
        std::cout << "Current bandwidth: " << bandwidth << " bps" << std::endl;
        startTime = endTime;
    }
}

std::atomic<bool> stop_capture(false);

void CPacketHandler::SigintHandler(int signum) {
    std::cout << "Interrupt signal (" << signum << ") received.\n";
    stop_capture = true;
}

int CPacketHandler::AnalyzeNetworkTraffic(const char *pcap_file) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(pcap_file, errbuf);
    if (handle == nullptr) {
        std::cerr << "Could not open pcap file: " << errbuf << std::endl;
        return ERROR_CANNOT_OPEN_FILE;
    }

    struct pcap_pkthdr *header;
    const u_char *data;
    int packetCount = 0;

    while (int res = pcap_next_ex(handle, &header, &data) >= 0) {
        if (res == 0) continue;
        PacketHandler(reinterpret_cast<u_char*>(this), header, data);
        packetCount++;
    }

    pcap_close(handle);
    return SUCCESS_CODE;
}

// 패킷을 분석하여 악성 여부를 판단하고 로그 파일에 기록
int CPacketHandler::AnalyzePacket(const struct ip* pIpHeader, const u_char* pPayload, int nPayloadLength, const std::string& strSrcIP) {
    bool bIsMalicious = false;
    bool payloadMalicious = false;
    bool ipFloodingDetected = false;
    bool randomIPDetected = false;
    bool largePacketDetected = false;
    bool fragmentationDetected = false;
    static int normalPacketCount = 0;
    static int abnormalPacketCount = 0;
    static auto lastCheckTime = std::chrono::steady_clock::now();
    auto currentTime = std::chrono::steady_clock::now();
    static std::unordered_set<std::string> loggedMessages; // 중복 메시지 추적
    static std::unordered_set<std::string> processedIPs; // 처리된 IP 추적
    static std::unordered_map<std::string, std::unordered_set<std::string>> ipAddressesForPayload;
    static int detectionCount = 0;

    std::ofstream logFile("logs/detailed_logs.log", std::ios_base::app);

    // 비정상 패킷이 정상 패킷보다 같은 시간 동안 2배 이상 많은지 확인
    if (bIsMalicious) {
        abnormalPacketCount++;
    } else {
        normalPacketCount++;
    }

    if (std::chrono::duration_cast<std::chrono::seconds>(currentTime - lastCheckTime).count() >= 60) {
        if (abnormalPacketCount > normalPacketCount * ABNORMAL_PACKET_RATIO) {
            std::string msg = "Abnormal packet count exceeds twice the normal packet count within the same time period.";
            if (loggedMessages.find(msg) == loggedMessages.end()) {
                logFile << msg << std::endl;
                std::cout << msg << std::endl;
                loggedMessages.insert(msg);
            }
        }
        normalPacketCount = 0;
        abnormalPacketCount = 0;
        lastCheckTime = currentTime;
    }

    std::string floodingIP = "";
    // 동일 IP 주소에서 과도한 패킷 발생 확인
    nIpFloodingCount[strSrcIP]++;
    if (nIpFloodingCount[strSrcIP] > FLOODING_THRESHOLD && processedIPs.find(strSrcIP + "-flooding") == processedIPs.end()) {
        std::string msg = "IP Flooding detected in " + strSrcIP;
        m_DuplicateIPCount++;
        logFile << msg << std::endl;
        loggedMessages.insert(msg);
        processedIPs.insert(strSrcIP + "-flooding");
        bIsMalicious = true;
        ipFloodingDetected = true;
        floodingIP = strSrcIP;
    }

    // 출발지 IP 주소를 해당 페이로드에 대한 집합에 추가
    std::string payloadString(reinterpret_cast<const char*>(pPayload), nPayloadLength);
    ipAddressesForPayload[payloadString].insert(strSrcIP);

    // 동일한 페이로드에 대해 출발지 IP 주소가 임계값 이상일 경우 무작위 출발지 IP로 간주
    if (ipAddressesForPayload[payloadString].size() > RANDOM_IP_THRESHOLD) {
        std::cout << "Random source IP detected for payload: " << payloadString << std::endl;
        randomIPDetected = true;
        bIsMalicious = true;
    }

    if (randomIPDetected) {
        std::cout << "Detected random IPs:" << std::endl;
        for (const auto& ip : ipAddressesForPayload[payloadString]) {
            std::cout << ip << std::endl;
        }
    }

    // 의미없는 형태의 값 (패킷의 크기를 의도적으로 크게 만들기 위한 목적)
    int aCount = std::count(pPayload, pPayload + nPayloadLength, 'A');

    // 페이로드의 70% 이상이 'A'로 채워져 있을 경우 악성으로 간주
    if (aCount >= 0.7 * nPayloadLength) payloadMalicious = true;

    if (payloadMalicious && processedIPs.find(strSrcIP + "-payload") == processedIPs.end()) {
        std::string msg = "Malicious payload detected in " + strSrcIP;
        strUniqueMaliciousIPs.insert(strSrcIP);
        m_MaliciousPayloadCount++;
        logFile << msg << std::endl;
        loggedMessages.insert(msg);
        processedIPs.insert(strSrcIP + "-payload");
        bIsMalicious = true;
    }

    // 큰 패킷 확인 및 동일한 크기의 패킷으로 구성
    int nIpLength = ntohs(pIpHeader->ip_len);
    static int previousPacketLength = -1;
    if (previousPacketLength == -1) {
        previousPacketLength = nIpLength;
    } else if (previousPacketLength != nIpLength) {
        largePacketDetected = false;
    } else {
        largePacketDetected = true;
    }
    if (nIpLength > MAX_PACKET_SIZE && processedIPs.find(strSrcIP + "-largePacket") == processedIPs.end()) {
        std::string msg = "Large packet detected in " + strSrcIP + ": " + std::to_string(nIpLength) + " bytes";
        m_LargePacketCount++;
        strUniqueLargeIPs.insert(strSrcIP);
        nLargePacketSizes.insert(nIpLength);
        logFile << msg << std::endl;
        loggedMessages.insert(msg);
        processedIPs.insert(strSrcIP + "-largePacket");
        bIsMalicious = true;
    }
    previousPacketLength = nIpLength;

    // 패킷 단편화 확인
    int nIpOffset = ntohs(pIpHeader->ip_off);
    if ((nIpOffset & IP_MF || (nIpOffset & IP_OFFMASK) != 0) && pIpHeader->ip_p != IPPROTO_TCP && nIpLength > MTU_SIZE && processedIPs.find(strSrcIP + "-fragmentation") == processedIPs.end()) {
        std::string msg = "Packet fragmentation detected: " + strSrcIP;
        logFile << msg << std::endl;
        loggedMessages.insert(msg);
        processedIPs.insert(strSrcIP + "-fragmentation");
        bIsMalicious = true;
        fragmentationDetected = true;
    }

    if (bIsMalicious && processedIPs.find(strSrcIP) == processedIPs.end()) {
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
        detectionCount++;
        std::string detectedRandomIP = randomIPDetected ? std::to_string(ipAddressesForPayload[payloadString].size()) + " different IPs" : "No";
        int aCount = std::count(pPayload, pPayload + nPayloadLength, 'A');
        std::string displayFloodingIP = !floodingIP.empty() ? floodingIP : "No";

        vt.addRow(
            std::to_string(detectionCount),
            std::to_string(nIpLength) + " bytes",
            detectedRandomIP,
            displayFloodingIP,
            fragmentationDetected ? "Yes" : "No",
            payloadMalicious ? std::to_string(aCount) + " bytes" : "No"
        );

        processedIPs.insert(strSrcIP);
        }

        logFile.close();
        return SUCCESS_CODE;
}

// 전역적으로 원래 버퍼를 저장할 변수
std::streambuf* originalCoutBuffer = nullptr;

// 출력을 비활성화하는 함수
void disableOutput() {
    originalCoutBuffer = std::cout.rdbuf();
    std::cout.rdbuf(nullptr);
}

// 출력을 다시 활성화하는 함수
void enableOutput() {
    std::cout.rdbuf(originalCoutBuffer);
}

int CPacketHandler::RunSystem(const char* interfaceName) {
    auto dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interfaceName);
    if (!dev) {
        std::cerr << "Cannot find interface: " << interfaceName << std::endl;
        return ERROR_CANNOT_FIND_INTERFACE;
    }

    if (!dev->open()) {
        std::cerr << "Cannot open device: " << interfaceName << std::endl;
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
        handler.CapturePackets(interfaceName);
        if (handler.PromptUserForPacketAnalysis()) {
            handler.AnalyzeCapturedPackets();
        }
    } else {
        std::cout << "No packets captured." << std::endl;
    }

    return SUCCESS_CODE;
}

bool CPacketHandler::PromptUserForPacketCapture() {
    char userInput;
    std::cout << COLOR_WHITE "\n## Do you want to capture the sent packets? (y/n): " << COLOR_RESET;
    std::cin >> userInput;
    return userInput == 'y' || userInput == 'Y';
}

bool CPacketHandler::PromptUserForPacketAnalysis() {
    char userInput;
    sleep(1);
    std::cout << COLOR_WHITE "## Do you want to analyze malicious packets among the captured packets? (y/n): " << COLOR_RESET;
    std::cin >> userInput;
    return userInput == 'y' || userInput == 'Y';
}

void CPacketHandler::CapturePackets(const char* interfaceName) {
    std::cout << COLOR_GREEN "Capturing packets on " << interfaceName << "... Press Ctrl+C to stop\n" << COLOR_RESET << std::endl;

    char errbuf[PCAP_ERRBUF_SIZE];
    auto pcapHandle = pcap_open_live(interfaceName, MAX_SNAP_LEN, 1, 10, errbuf);
    if (!pcapHandle) {
        std::cerr << "Couldn't open device " << interfaceName << ": " << errbuf << std::endl;
        return;
    }

    auto pcapDumper = pcap_dump_open(pcapHandle, "captured_packets.pcap");
    if (!pcapDumper) {
        std::cerr << "Couldn't open output file: " << pcap_geterr(pcapHandle) << std::endl;
        return;
    }

    signal(SIGINT, CPacketHandler::SigintHandler);

    auto pcapCallback = [](u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
        pcap_dump(userData, pkthdr, packet);
    };

    while (!stop_capture) {
        pcap_dispatch(pcapHandle, 0, pcapCallback, (u_char*)pcapDumper);
    }

    pcap_dump_close(pcapDumper);
    pcap_close(pcapHandle);

    std::cout << "Packets captured and saved to " << COLOR_YELLOW << "'captured_packets.pcap'." << COLOR_RESET << "\n" << std::endl;
}

void CPacketHandler::AnalyzeCapturedPackets() {
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
}

bool CPacketHandler::PromptUserForBlockingIPs() {
    char userInput;
    sleep(1);
    std::cout << COLOR_RED "\n## Do you want to block the detected malicious IPs? (y/n): " << COLOR_RESET;
    std::cin >> userInput;
    if (userInput == 'y' || userInput == 'Y') {
        return true;
    } else {
        std::cout << "No IPs blocked." << std::endl;
        return false;
    }
}

void CPacketHandler::BlockDetectedIPs() {
    std::ifstream infile("logs/malicious_ips.log");
    if (!infile.is_open()) {
        std::cerr << "Could not open malicious_ips.log for reading." << std::endl;
        return;
    }

    std::string ip;
    while (std::getline(infile, ip)) {
        disableOutput();
        int sshInputResult = ::RunIptables("INPUT", ip, "22", "ACCEPT");
        int sshOutputResult = ::RunIptables("OUTPUT", ip, "22", "ACCEPT");
        enableOutput();
        if (sshInputResult != SUCCESS_CODE || sshOutputResult != SUCCESS_CODE) {
            std::cerr << "Failed to set SSH exception for IP " << ip << "." << std::endl;
            continue;
        }
        int result = ::RunIptables("INPUT", ip, "80", "DROP");
        if (result == SUCCESS_CODE) {
            std::cout << "IP " << ip << " has been blocked successfully.\n" << std::endl;
        } else {
            std::cerr << "Failed to block IP " << ip << "." << std::endl;
        }
    }

    infile.close();
}