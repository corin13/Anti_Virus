#pragma once

#include <netinet/ip.h>
#include <Packet.h>
#include <pcap.h>
#include <PcapLiveDevice.h>
#include <PcapLiveDeviceList.h>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include "ansi_color.h"
#include "config.h"
#include "email_sender.h"
#include "error_codes.h"
#include "firewall.h"
#include "logfile_manager.h"
#include "log_parser.h"
#include "packet_generator.h"
#include "user_program.h"
#include "VariadicTable.h"

#define COLUMN_WIDTH 30
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

    void DisableOutput();
    void EnableOutput();
    void GetBlockedIPs();
    static int MonitorBandwidth();
    bool PromptUserForPacketCapture();
    bool PromptUserForPacketAnalysis();
    static void SigintHandler(int signum);
    int AnalyzeCapturedPackets(bool bBlockIPs);
    void SaveBlockedIP(const std::string& strIp);
    int CapturePackets(const char* interfaceName);
    static int RunSystem(const char* interfaceName);
    int AnalyzeNetworkTraffic(const char *pcap_file, bool bBlockIPs);
    static int LogPacket(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* dev, void* userCookie);
    static int PacketHandler(u_char *pUserData, const struct pcap_pkthdr* pPkthdr, const u_char* pPacket, bool bBlockIPs);
    int AnalyzePacket(const struct ip* pIpHeader, const u_char* pPayload, int nPayloadLength, const std::string& strSrcIP, bool bBlockIPs);
    void ProcessPacket(CPacketHandler *pHandler, const struct ip* pIpHeader, int nPayloadLength, const u_char* pPayload, const std::string& srcIP, bool bBlockIPs);

    int m_DetectionCount;
    VariadicTable<std::string, std::string, std::string, std::string, std::string, std::string> vt;

private:
    int m_DuplicateIPCount;
    int m_LargePacketCount;
    int m_NormalPacketCount;
    int m_AbnormalPacketCount;
    int m_MaliciousPacketCount;
    int m_MaliciousPayloadCount;
    static std::streambuf* originalCoutBuffer;
    std::unordered_set<int> nLargePacketSizes;
    std::unordered_set<std::string> strRecentIPs;
    std::unordered_set<std::string> strLoggedIPs;
    std::unordered_set<std::string> strProcessedIPs;
    std::unordered_set<std::string> strUniqueLargeIPs;
    std::unordered_set<std::string> strLoggedMessages;
    std::chrono::steady_clock::time_point lastCheckTime;
    std::unordered_set<std::string> strUniqueMaliciousIPs;
    std::unordered_map<std::string, int> nIpFloodingCount;
    std::unordered_set<std::string> blockedIPs;
    std::unordered_map<std::string, std::unordered_set<std::string>> strIpAddressesForPayload;
};