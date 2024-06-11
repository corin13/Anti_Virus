#pragma once

#include <netinet/ip.h>
#include <pcap.h>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <Packet.h>
#include <PcapLiveDevice.h>
#include <PcapLiveDeviceList.h>
#include <vector>
#include "ansi_color.h"
#include "error_codes.h"
#include "VariadicTable.h"
#include "logfile_manager.h"

#define COLUMN_WIDTH 30
#define HALF_WORD_SIZE 16
#define HALF_WORD_MASK 0xFFFF
#define ETHERNET_HEADER_LENGTH 14
#define IP_HEADER_LENGTH_UNIT 4
#define PACKET_BUFFER_SIZE 4096
#define IP_HEADER_LENGTH 5
#define IP_VERSION 4
#define BITS_PER_BYTE 8
#define IP_TTL 255
#define MAX_PACKET_SIZE 1472
#define IP_MORE_FRAGMENTS 0x2000
#define IP_TYPE_OF_SERVICE 0
#define SOURCE_PORT 12345
#define DESTINATION_PORT 54321
#define MAX_PACKET_ID 65535
#define MAX_SNAP_LEN 65536
#define TRANSMISSION_DURATION 10
#define TRANSMISSION_INTERVAL 250
#define MAX_SEGMENT_VALUE 256
#define PACKETS_PER_INTERVAL 1240
#define PAYLOAD_PATTERN "AAAAAAAAAA"
#define MTU_SIZE 1500
#define FLOODING_THRESHOLD 10
#define RANDOM_IP_THRESHOLD 100
#define ABNORMAL_PACKET_RATIO 2

class CPacketHandler {
public:
    CPacketHandler();
    ~CPacketHandler();

    int AnalyzeNetworkTraffic(const char *pcap_file);
    static void PacketHandler(u_char *pUserData, const struct pcap_pkthdr* pPkthdr, const u_char* pPacket);
    static void LogPacket(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* dev, void* userCookie);
    static void MonitorBandwidth();
    static void SendMaliciousPacket(const char* src_ip, const char* dst_ip, int packet_count, std::ofstream& logFile);
    static void GenerateMaliciousPackets(std::atomic<int>& totalMaliciousPacketsSent);
    static void SigintHandler(int signum);
    static int RunSystem(const char* interfaceName);
    int RunIptables(std::string direction, std::string ip, std::string port, std::string action);
    static void ProcessPacket(CPacketHandler *pHandler, const struct ip* pIpHeader, int nPayloadLength, const u_char* pPayload, const std::string& srcIP);

private:
    int AnalyzePacket(const struct ip* pIpHeader, const u_char* pPayload, int nPayloadLength, const std::string& strSrcIP);
    bool PromptUserForPacketCapture();
    bool PromptUserForPacketAnalysis();
    void CapturePackets(const char* interfaceName);
    void AnalyzeCapturedPackets();
    bool PromptUserForBlockingIPs();
    void BlockDetectedIPs();

    std::unordered_set<std::string> strRecentIPs;
    std::unordered_map<std::string, std::unordered_set<int>> strIpProtocolHistory;
    std::unordered_map<std::string, int> nIpFloodingCount;
    std::unordered_set<std::string> strUniqueMaliciousIPs;
    std::unordered_map<std::string, std::vector<int>> strProtocolChangeHistory;
    std::unordered_set<std::string> strUniqueLargeIPs;
    std::unordered_set<int> nLargePacketSizes;
    std::unordered_set<std::string> strLoggedSuspiciousIPs;
    std::unordered_set<std::string> strLoggedIPs;
    int m_DuplicateIPCount = 0;
    int m_LargePacketCount = 0;
    int m_MaliciousPayloadCount = 0;
    int m_MaliciousPacketCount = 0;

    VariadicTable<std::string, std::string, std::string, std::string, std::string, std::string> vt;
};