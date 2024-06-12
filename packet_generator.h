#pragma once

#include <atomic>
#include <fstream>
#include <netinet/in.h>
#include "ansi_color.h"

#define PACKET_BUFFER_SIZE 4096
#define IP_HEADER_LENGTH 5
#define IP_VERSION 4
#define IP_TYPE_OF_SERVICE 0
#define MAX_PACKET_SIZE 1472 
#define IP_MORE_FRAGMENTS 0x2000
#define SOURCE_PORT 12345
#define DESTINATION_PORT 54321
#define MAX_PACKET_ID 65535
#define MAX_SEGMENT_VALUE 256
#define PACKETS_PER_INTERVAL 1240
#define TRANSMISSION_DURATION 10
#define TRANSMISSION_INTERVAL 250


void GenerateMaliciousPackets(std::atomic<int>& totalMaliciousPacketsSent);
void SendMaliciousPacket(const char* src_ip, const char* dst_ip, int packet_count, std::ofstream& logFile);