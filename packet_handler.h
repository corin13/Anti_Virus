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
#include "firewall.h"
#include "packet_generator.h"
#include "user_program.h"

#define COLUMN_WIDTH 30
#define HALF_WORD_SIZE 16
#define HALF_WORD_MASK 0xFFFF
#define ETHERNET_HEADER_LENGTH 14
#define IP_HEADER_LENGTH_UNIT 4
#define BITS_PER_BYTE 8
#define PACKET_IP_TTL 255
#define MAX_PACKET_SIZE 1472
#define MAX_SNAP_LEN 65536
#define PAYLOAD_PATTERN "AAAAAAAAAA"
#define MTU_SIZE 1500
#define FLOODING_THRESHOLD 10
#define RANDOM_IP_THRESHOLD 50
#define ABNORMAL_PACKET_RATIO 2

class CPacketHandler {
public:
    CPacketHandler();
    ~CPacketHandler();

    int AnalyzeNetworkTraffic(const char *pcap_file);
    static void PacketHandler(u_char *pUserData, const struct pcap_pkthdr* pPkthdr, const u_char* pPacket);
    static void LogPacket(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* dev, void* userCookie);
    static void MonitorBandwidth();
    static void SigintHandler(int signum);
    static int RunSystem(const char* interfaceName);
    int RunIptables(std::string direction, std::string ip, std::string port, std::string action);
    void ProcessPacket(CPacketHandler *pHandler, const struct ip* pIpHeader, int nPayloadLength, const u_char* pPayload, const std::string& srcIP);
    bool PromptUserForPacketCapture();
    bool PromptUserForPacketAnalysis();
    void CapturePackets(const char* interfaceName);
    void AnalyzeCapturedPackets();
    int AnalyzePacket(const struct ip* pIpHeader, const u_char* pPayload, int nPayloadLength, const std::string& strSrcIP);
    bool PromptUserForBlockingIPs();
    void BlockDetectedIPs();

private:
    int m_DuplicateIPCount;
    int m_LargePacketCount;
    int m_MaliciousPayloadCount;
    int m_MaliciousPacketCount;
    std::unordered_set<std::string> strRecentIPs;
    std::unordered_map<std::string, std::unordered_set<int>> strIpProtocolHistory;
    std::unordered_map<std::string, int> nIpFloodingCount;
    std::unordered_set<std::string> strUniqueMaliciousIPs;
    std::unordered_map<std::string, std::vector<int>> strProtocolChangeHistory;
    std::unordered_set<std::string> strUniqueLargeIPs;
    std::unordered_set<int> nLargePacketSizes;
    std::unordered_set<std::string> strLoggedSuspiciousIPs;
    std::unordered_set<std::string> strLoggedIPs;

    VariadicTable<std::string, std::string, std::string, std::string, std::string, std::string> vt;
};