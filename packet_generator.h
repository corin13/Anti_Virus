#pragma once

#include <atomic>
#include <fstream>
#include <netinet/in.h>
#include "ansi_color.h"
#include "error_codes.h"
#include "logfile_manager.h"

#define HALF_WORD_SIZE 16
#define HALF_WORD_MASK 0xFFFF
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


class CPacketGenerator {
public: 
    int GenerateMaliciousPackets(std::atomic<int>& totalMaliciousPacketsSent);
    int SendMaliciousPacket(const char* src_ip, const char* dst_ip, int packet_count, std::ofstream& logFile);
};