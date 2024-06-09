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

// 패킷 페이로드에 악성 패턴 포함 여부 확인
bool CPacketHandler::CheckPayload(const u_char *pPayload, int nSize) {
    for (int i = 0; i <= nSize - 4; i++) { 
        if (memcmp(pPayload + i, PAYLOAD_PATTERN, 4) == 0) { 
            return true; 
        }
    }
    return false; 
}

// IP 주소의 변화가 빈번한지 확인
bool CPacketHandler::CheckRandomIPs(const std::string& strSrcIP) {
    if (strRecentIPs.find(strSrcIP) == strRecentIPs.end()) { 
        if (strRecentIPs.size() > 100) { 
            strRecentIPs.clear(); 
        }
        strRecentIPs.insert(strSrcIP); 
        return true; 
    }
    return false; 
}

// 동일한 IP 주소에서 패킷이 과도하게 발생하는지 확인
bool CPacketHandler::CheckIPFlooding(const std::string& strSrcIP) {
    nIpFloodingCount[strSrcIP]++; 
    if (nIpFloodingCount[strSrcIP] > 10) { 
        nDuplicateIPCount++; 
        return true;
    }
    return false; 
}

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

// 패킷을 분석하여 악성 여부를 판단하고 로그 파일에 기록
int CPacketHandler::AnalyzePacket(const struct ip*  pIpHeader, const u_char* pPayload, int nPayloadLength, const std::string& strSrcIP) {
    bool bIsMalicious = false; 

    std::ofstream logFile("detailed_logs.log", std::ios_base::app); 

    if (CheckIPFlooding(strSrcIP)) {
        bIsMalicious = true;
        strUniqueMaliciousIPs.insert(strSrcIP);
        logFile << "IP Flooding detected: " << strSrcIP << std::endl;
    }

    // 큰 패킷 확인
    int nIpLength = ntohs(pIpHeader->ip_len); 
    if (nIpLength > MAX_PACKET_SIZE) { 
        bIsMalicious = true; 
        nLargePacketCount++;
        strUniqueLargeIPs.insert(strSrcIP); 
        nLargePacketSizes.insert(nIpLength); 
        logFile << "Large packet detected: " << nIpLength << " bytes from " << strSrcIP << std::endl;
    }

    int nProtocol = pIpHeader->ip_p;
    strIpProtocolHistory[strSrcIP].insert(nProtocol);
    if (strIpProtocolHistory[strSrcIP].size() > 3) {
        strProtocolChangeHistory[strSrcIP].assign(strIpProtocolHistory[strSrcIP].begin(), strIpProtocolHistory[strSrcIP].end());
        bIsMalicious = true;
        logFile << "Random protocol change detected: " << strSrcIP << std::endl;
    }

    // UDP 프로토콜의 경우 추가 확인
    if (pIpHeader->ip_p == IPPROTO_UDP) {
        const struct udphdr* pUdpHeader = (struct udphdr*)(pPayload - pIpHeader->ip_hl * 4); 
        if (CheckPayload(pPayload, nPayloadLength)) { 
            bIsMalicious = true; 
            strUniqueMaliciousIPs.insert(strSrcIP); 
            nMaliciousPayloadCount++; 
            logFile << "Malicious payload detected: " << strSrcIP << std::endl;
        }

        if (CheckRandomIPs(strSrcIP)) { 
            bIsMalicious = true; 
            logFile << "Frequent IP change detected: " << strSrcIP << std::endl;
        }

        int nIpOffset = ntohs(pIpHeader->ip_off); 
        if (nIpOffset & IP_MF || (nIpOffset & IP_OFFMASK) != 0) { 
            logFile << "UDP fragmentation: " << strSrcIP << std::endl;
        }

        int nDstPort = ntohs(pUdpHeader->dest);
        if (nDstPort == UDP_PORT_HTTP) {
            if (strLoggedSuspiciousIPs.find(strSrcIP) == strLoggedSuspiciousIPs.end()) {
                strLoggedSuspiciousIPs.insert(strSrcIP);
            }
            bIsMalicious = true;
            strUniqueMaliciousIPs.insert(strSrcIP);
            logFile << "Suspicious UDP packet on HTTP port: " << strSrcIP << std::endl;
        }
    } else if (pIpHeader->ip_p == IPPROTO_ICMP) {
        if (CheckPayload(pPayload, nPayloadLength)) {
            bIsMalicious = true;
            strUniqueMaliciousIPs.insert(strSrcIP);
            nMaliciousPayloadCount++;
            logFile << "Malicious payload detected: " << strSrcIP << std::endl;
        }

        if (CheckRandomIPs(strSrcIP)) {
            bIsMalicious = true;
            logFile << "Frequent IP change detected: " << strSrcIP << std::endl;
        }
    }

    if (bIsMalicious) {
        nMaliciousPacketCount++;

        if (strLoggedIPs.find(strSrcIP) == strLoggedIPs.end()) {
            std::ofstream outfile;
            outfile.open("malicious_ips.log", std::ios_base::app);

            if (!outfile.is_open()) {
                return ERROR_CANNOT_OPEN_FILE;
            }
            outfile << strSrcIP << std::endl;
            outfile.close();
            strLoggedIPs.insert(strSrcIP);
        }
    }
    logFile.close();
    return SUCCESS_CODE;
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

// 비정상 패킷을 생성하는 함수
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
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + 512); // 단편화된 패킷 크기
    iph->id = htonl(rand() % 65535); // 임의의 패킷 ID
    iph->frag_off = htons(0x2000); // 단편화 설정
    iph->ttl = 255;
    iph->protocol = IPPROTO_UDP; 
    iph->check = 0; 
    iph->saddr = inet_addr(src_ip);
    iph->daddr = sin.sin_addr.s_addr;

    // UDP 헤더 설정 추가
    udph->source = htons(12345);
    udph->dest = htons(54321);
    udph->len = htons(sizeof(struct udphdr) + 512); // UDP 헤더 + 데이터 길이
    udph->check = 0; 

    // 데이터 설정 (의미 없는 값으로 채우기)
    memset(packet + sizeof(struct iphdr) + sizeof(struct udphdr), 'A', 512); 

    // IP 체크섬 계산
    iph->check = CheckSum((unsigned short *)packet, sizeof(struct iphdr) + sizeof(struct udphdr) + 512);

    for (int i = 0; i < packet_count; i++) {
        if (sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct udphdr) + 512, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) { // 패킷 크기 수정
            perror("Packet send failed");
        } else {
            logFile << "Packet sent from " << src_ip << " to " << dst_ip << std::endl;
        }
    }

    close(sock);
}

// 비정상 패킷을 지속적으로 생성하고 전송하는 함수
void CPacketHandler::GenerateMaliciousPackets() {
    const char* src_ips[] = {"192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5", "192.168.1.6"};
    const int src_ip_count = sizeof(src_ips) / sizeof(src_ips[0]);
    const char* dst_ip = "192.168.1.1"; 
    const int normal_packet_count = 50;
    const int malicious_packet_count = normal_packet_count * 2;

    while (true) {
        std::ofstream logFile("packet_transmission.log", std::ios_base::app);
        logFile << "sending packets.." << std::endl;
        for (int i = 0; i < malicious_packet_count; i++) {
            const char* src_ip = src_ips[i % src_ip_count];
            SendMaliciousPacket(src_ip, dst_ip, 1, logFile);
        }
        logFile.close();
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

volatile sig_atomic_t stop_capture = 0;

void CPacketHandler::SigintHandler(int signum) {
    std::cout << "Interrupt signal (" << signum << ") received.\n";
    stop_capture = 1;
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

    // 패킷 핸들러 객체 생성
    CPacketHandler handler;

    // 로그 파일 초기화
    std::ofstream logFile("malicious_packets.log", std::ios_base::trunc);
    logFile.close();

    // 패킷 생성 스레드 시작
    std::thread packetThread(CPacketHandler::GenerateMaliciousPackets);

    std::cout << COLOR_RED "Generating and sending malicious packets...\n" << COLOR_RESET << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(5)); 

    // 패킷 생성 스레드 종료
    packetThread.detach();

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
        pcapHandle = pcap_open_live(interfaceName, BUFSIZ, 1, 1000, errbuf);
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

        std::cout << COLOR_GREEN "Analyzing captured packets for malicious content..." << COLOR_RESET << std::endl;
        int result = handler.AnalyzeNetworkTraffic("captured_packets.pcap"); // 캡처된 패킷 파일 경로

        if (result == SUCCESS_CODE) {
            std::cout << COLOR_GREEN "Packet analysis completed successfully." << COLOR_RESET << std::endl;
        } else {
            std::cerr << "Packet analysis failed with error code: " << result << std::endl;
        }
    } else {
        std::cout << "No packets captured." << std::endl;
    }

    return 0;
}