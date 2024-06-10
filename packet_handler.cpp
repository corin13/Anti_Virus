#include <arpa/inet.h> 
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstring>
#include <iomanip>
#include <iostream> 
#include <IPv4Layer.h>
#include <Packet.h>
#include <pcap.h> 
#include <PcapLiveDevice.h>
#include <PcapLiveDeviceList.h>
#include <fstream> 
#include <netinet/ip.h>
#include <netinet/ip_icmp.h> 
#include <netinet/udp.h> 
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
      vt({"No", "Packet Size", "Random src IP", "IP Flooding", "Fragmentation", "Data"}, 30) {}

CPacketHandler::~CPacketHandler() {}

// IP 헤더의 체크섬을 계산
unsigned short CheckSum(void *b, int len) {
    unsigned short *buf = (unsigned short*)b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }
    if (len == 1) {
        sum += *(unsigned char*)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// pcap 패킷 처리 핸들러 함수
void CPacketHandler::PacketHandler(u_char *pUserData, const struct pcap_pkthdr* pPkthdr, const u_char* pPacket) {
    CPacketHandler *pHandler = reinterpret_cast<CPacketHandler*>(pUserData); 
    const struct ip* pIpHeader = (struct ip*)(pPacket + 14); 
    int nIpHeaderLength = pIpHeader->ip_hl * 4; 
    int nIpTotalLength = ntohs(pIpHeader->ip_len); 
    int nPayloadLength = nIpTotalLength - nIpHeaderLength;
    const u_char* pPayload = pPacket + 14 + nIpHeaderLength; 
	std::string strSrcIP = inet_ntoa(pIpHeader->ip_src); 
		
	pHandler->AnalyzePacket(pIpHeader, pPayload, nPayloadLength, strSrcIP); 
} 

// 글로벌 변수
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

        // 총 바이트 수에 패킷 크기 추가
        totalBytes += packetLen;

        // IP 헤더 가져오기
        const struct ip* pIpHeader = (struct ip*)ipLayer->getData();
        int nPayloadLength = packetLen - (pIpHeader->ip_hl * 4);
        const u_char* pPayload = (const u_char*)ipLayer->getData() + (pIpHeader->ip_hl * 4);

        handler->AnalyzePacket(pIpHeader, pPayload, nPayloadLength, srcIP);
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
        double bandwidth = (bytes * 8) / elapsedSeconds.count();  // 대역폭(bps) 계산
        
        std::cout << "Current bandwidth: " << bandwidth << " bps" << std::endl;
        startTime = endTime;
    }
}

// 비정상 패킷을 지속적으로 생성하는 함수
void CPacketHandler::GenerateMaliciousPackets(std::atomic<int>& totalMaliciousPacketsSent) {
    const char* dst_ip = "192.168.1.1";

    // 랜덤 시드 설정
    srand(static_cast<unsigned int>(time(0)));

    std::ofstream logFile("logs/packet_transmission.log", std::ios_base::app);
    logFile << "Sending packets..." << std::endl;
    std::cout << COLOR_RED "Generating and sending malicious packets...\n" << COLOR_RESET << std::endl;

    auto startTime = std::chrono::steady_clock::now();

    while (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - startTime).count() < 10) {
        for (int i = 0; i < 1240; i++) {
            std::string src_ip = "192.168." + std::to_string(rand() % 256) + "." + std::to_string(rand() % 256);
            SendMaliciousPacket(src_ip.c_str(), dst_ip, 1, logFile);
            totalMaliciousPacketsSent++;
            std::cout << "\rTotal malicious packets sent: " << totalMaliciousPacketsSent.load() << std::flush;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    logFile << "Total malicious packets sent: " << totalMaliciousPacketsSent.load() << std::endl;
    std::cout << "\nTotal malicious packets sent: " << totalMaliciousPacketsSent.load() << std::endl;
    logFile.close();
}

// 비정상 패킷을 전송하는 함수
void CPacketHandler::SendMaliciousPacket(const char* src_ip, const char* dst_ip, int packet_count, std::ofstream& logFile) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(1);
    }

    char packet[4096];
    memset(packet, 0, 4096);

    // UDP 헤더 설정 
    struct iphdr *iph = (struct iphdr *)packet;
    struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));
    struct sockaddr_in sin;

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(dst_ip);

    // IP 헤더 설정
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + 1472); // 모든 패킷은 540바이트로 동일한 크기의 패킷으로 구성 (IP헤더 + UDP헤더 + 데이터)
    iph->id = htonl(rand() % 65535); // 임의의 패킷 ID
    iph->frag_off = htons(0x2000); // 단편화 플래그 설정 (More Fragments)
    iph->ttl = 255;
    iph->protocol = IPPROTO_UDP; 
    iph->check = 0; 
    iph->saddr = inet_addr(src_ip);
    iph->daddr = sin.sin_addr.s_addr;

    // UDP 헤더 설정
    udph->source = htons(12345);
    udph->dest = htons(54321);
    udph->len = htons(sizeof(struct udphdr) + 1472); // UDP 헤더 + 데이터 길이
    udph->check = 0; 

    // 의미 없는 형태의 값 (패킷의 크기를 의도적으로 크게 만들기 위한 목적)
    memset(packet + sizeof(struct iphdr) + sizeof(struct udphdr), 'A', 1472); 

    // IP 체크섬 계산
    iph->check = CheckSum((unsigned short *)packet, sizeof(struct iphdr) + sizeof(struct udphdr) + 1472);

    for (int i = 0; i < packet_count; i++) {
        if (sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct udphdr) + 1472, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) { // 패킷 크기 수정
            perror("Packet send failed");
        } else {
            logFile << "Packet sent from " << src_ip << " to " << dst_ip << std::endl;
        }
    }

    close(sock);
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
        if (res == 0) {
            continue; 
        }

        PacketHandler(reinterpret_cast<u_char*>(this), header, data);
        packetCount++;
    }

    pcap_close(handle);
    return SUCCESS_CODE;
}

// 패킷을 분석하여 악성 여부를 판단하고 로그 파일에 기록
int CPacketHandler::AnalyzePacket(const struct ip* pIpHeader, const u_char* pPayload, int nPayloadLength, const std::string& strSrcIP) {
    bool bIsMalicious = false;
    bool payloadMalicious = true;
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
    // IP flooding을 탐지하고 관리하는 자료구조 선언
    std::unordered_map<std::string, bool> ipFloodingDetectedMap;
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
        std::cout << msg << std::endl;
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
    int aCount = 0;
    payloadMalicious = false;
    for (int i = 0; i < nPayloadLength; i++) {
        if (pPayload[i] == 'A') {
            aCount++;
        }
    }

    // 페이로드의 70% 이상이 'A'로 채워져 있을 경우 악성으로 간주
    if (aCount >= 0.7 * nPayloadLength) {
        payloadMalicious = true;
    }

    if (payloadMalicious && processedIPs.find(strSrcIP + "-payload") == processedIPs.end()) {
        std::string msg = "Malicious payload detected in " + strSrcIP;
        strUniqueMaliciousIPs.insert(strSrcIP);
        m_MaliciousPayloadCount++;
        logFile << msg << std::endl;
        std::cout << msg << std::endl;
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
        std::cout << msg << std::endl;
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
        std::cout << msg << std::endl;
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
            if (!outfile.is_open()) {
                return ERROR_CANNOT_OPEN_FILE;
            }
            outfile << strSrcIP << std::endl;
            outfile.close();
            strLoggedIPs.insert(strSrcIP);
        }

        // 탐지된 패킷 정보를 표에 추가
        detectionCount++;
        std::string detectedRandomIP = randomIPDetected ? std::to_string(ipAddressesForPayload[payloadString].size()) + " different IPs" : "No";
        int nIpLength = ntohs(pIpHeader->ip_len);
        int aCount = std::count(pPayload, pPayload + nPayloadLength, 'A'); // 'A'의 개수를 계산
        std::string displayFloodingIP = !floodingIP.empty() ? floodingIP : "No";

        vt.addRow(
            std::to_string(detectionCount),
            std::to_string(nIpLength) + " bytes",
            detectedRandomIP,
            displayFloodingIP,
            fragmentationDetected ? "Yes" : "No",
            payloadMalicious ? std::to_string(aCount) + " bytes" : "No" // 'A'가 몇 바이트 들어있는지 출력
        );

        // 악성 여부 판단에 대한 결과 출력
        std::cout << "Malicious packet detected: " << strSrcIP << std::endl;
        logFile << "Malicious packet detected: " << strSrcIP << std::endl;
        if (payloadMalicious) {
            std::cout << "- Reason: Malicious payload" << std::endl;
            logFile << "- Reason: Malicious payload" << std::endl;
        }
        if (ipFloodingDetected) {
            std::cout << "- Reason: IP Flooding" << std::endl;
            logFile << "- Reason: IP Flooding" << std::endl;
        }
        if (randomIPDetected) {
            std::cout << "- Reason: Random source IP" << std::endl;
            logFile << "- Reason: Random source IP" << std::endl;
        }
        if (largePacketDetected) {
            std::cout << "- Reason: Large packet" << std::endl;
            logFile << "- Reason: Large packet" << std::endl;
        }
        if (fragmentationDetected) {
            std::cout << "- Reason: Packet fragmentation" << std::endl;
            logFile << "- Reason: Packet fragmentation" << std::endl;
        }
 
        processedIPs.insert(strSrcIP); // Add IP to processed set
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

    // 네트워크 인터페이스 가져오기
    pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interfaceName);
    if (dev == nullptr) {
        std::cerr << "Cannot find interface: " << interfaceName << std::endl;
        return 1;
    }

    // 네트워크 인터페이스 열기
    if (!dev->open()) {
        std::cerr << "Cannot open device: " << interfaceName << std::endl;
        return 1;
    }

    std::atomic<int> packetCount(0);

    // 패킷 핸들러 객체 생성
    CPacketHandler handler;

    // 로그 파일 초기화
    std::ofstream logFile("logs/malicious_packets.log", std::ios_base::trunc);
    logFile.close();

    // 패킷 생성 스레드 시작
    std::atomic<int> totalMaliciousPacketsSent(0);
    std::thread packetThread(&CPacketHandler::GenerateMaliciousPackets, std::ref(totalMaliciousPacketsSent));
    packetThread.join();

    char userInput;
    std::cout << COLOR_RED "Do you want to capture the sent packets? (y/n): " << COLOR_RESET;
    std::cin >> userInput;

    if (userInput == 'y' || userInput == 'Y') {
        std::cout << COLOR_RED "Capturing packets on " << interfaceName << "... Press Ctrl+C to stop" << COLOR_RESET << std::endl;

        // pcap 파일로 저장할 준비
        pcap_t *pcapHandle;
        pcap_dumper_t *pcapDumper;
        char errbuf[PCAP_ERRBUF_SIZE];

        // 네트워크 인터페이스로부터 pcap handle 가져오기
        pcapHandle = pcap_open_live(interfaceName, 65536, 1, 10, errbuf);
        if (pcapHandle == nullptr) {
            std::cerr << "Couldn't open device " << interfaceName << ": " << errbuf << std::endl;
            return 1;
        }

        // pcap 파일로 저장할 dumper 설정
        pcapDumper = pcap_dump_open(pcapHandle, "captured_packets.pcap");
        if (pcapDumper == nullptr) {
            std::cerr << "Couldn't open output file: " << pcap_geterr(pcapHandle) << std::endl;
            return 1;
        }

        // 패킷 캡처 콜백 함수
        auto pcapCallback = [](u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
            pcap_dump(userData, pkthdr, packet);
        };

        // 패킷 캡처 시작
        signal(SIGINT, CPacketHandler::SigintHandler);

        while (!stop_capture) {
            pcap_dispatch(pcapHandle, 0, pcapCallback, (u_char*)pcapDumper);
        }

        // 캡처 중지 및 pcap handle 종료
        pcap_dump_close(pcapDumper);
        pcap_close(pcapHandle);

        std::cout << "Packets captured and saved to 'captured_packets.pcap'.\n" << std::endl;

        std::cout << COLOR_GREEN "Do you want to analyze the captured packets? (y/n): " << COLOR_RESET;
        std::cin >> userInput;

        if (userInput == 'y' || userInput == 'Y') {
            std::cout << COLOR_GREEN "Analyzing captured packets for malicious content..." << COLOR_RESET << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(5)); 
            
            int result = handler.AnalyzeNetworkTraffic("captured_packets.pcap"); // 캡처된 패킷 파일 경로

            if (result == SUCCESS_CODE) {
                std::cout << COLOR_GREEN "Packet analysis completed successfully." << COLOR_RESET << std::endl;
            } else {
                std::cerr << "Packet analysis failed with error code: " << result << std::endl;
            }

            // 테이블 출력 추가
            handler.vt.print(std::cout);

            // 차단 여부를 묻는 부분 추가
            std::cout << COLOR_RED "Do you want to block the detected malicious IPs? (y/n): " << COLOR_RESET;
            std::cin >> userInput;

            if (userInput == 'y' || userInput == 'Y') {
                std::ifstream infile("logs/malicious_ips.log");
                if (!infile.is_open()) {
                    std::cerr << "Could not open malicious_ips.log for reading." << std::endl;
                    return ERROR_CANNOT_OPEN_FILE;
                }

                std::string ip;
                while (std::getline(infile, ip)) {
                    disableOutput();
                    int sshInputResult = handler.RunIptables("INPUT", ip, "22", "ACCEPT");
                    int sshOutputResult = handler.RunIptables("OUTPUT", ip, "22", "ACCEPT");
                    enableOutput();
                    if (sshInputResult != SUCCESS_CODE || sshOutputResult != SUCCESS_CODE) {
                    std::cerr << "Failed to set SSH exception for IP " << ip << "." << std::endl;
                    continue;
                    }
                    int result = handler.RunIptables("INPUT", ip, "ANY", "DROP");
                    if (result == SUCCESS_CODE) {
                        std::cout << "IP " << ip << " has been blocked successfully.\n" << std::endl;
                    } else {
                        std::cerr << "Failed to block IP " << ip << "." << std::endl;
                    }
                }

                infile.close();
            } else {
                std::cout << "No IPs were blocked." << std::endl;
            }
        } else {
            std::cout << "No packets analyzed." << std::endl;
        }
    } else {
        std::cout << "No packets captured." << std::endl;
    }

    return 0;
}

int CPacketHandler::RunIptables(std::string direction, std::string ip, std::string port, std::string action){
    
    std::string iptablesCmd="iptables -A";

    if (direction == "INPUT"){
        iptablesCmd += " INPUT ";
        iptablesCmd += ip == "ANY" ? "" : "-s "+ ip;
    }
    else if (direction == "OUTPUT"){
        iptablesCmd += " OUTPUT ";
        iptablesCmd += ip == "ANY" ? "" : "-d "+ ip;
    }
    else {
        std::cerr << "Invalid Direction" << std::endl;
        return ERROR_INVALID_OPTION;
    }

    iptablesCmd += port == "ANY" ? "" : " -p tcp --dport " + port;

    if (action =="DROP"){
        iptablesCmd += " -j DROP";
    }
    else if (action == "ACCEPT"){
        iptablesCmd += " -j ACCEPT";
    }
    else {
        std::cerr << "Invalid Action" << std::endl;
        return ERROR_INVALID_OPTION;
    }

    std::cout << iptablesCmd << std::endl;

    FILE* pipe = popen(iptablesCmd.c_str(), "r");
    if (!pipe) {
        std::cerr << "ERROR : popen() failed" << std::endl;
        return ERROR_IPTABLES_COMMAND;
    }

    char buffer[128];

    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        std::cout << buffer;
    }

    pclose(pipe);

    return SUCCESS_CODE;
}