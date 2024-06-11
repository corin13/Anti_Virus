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

#define MAX_PACKET_SIZE 1000 
#define UDP_PORT_HTTP 80 
#define PAYLOAD_PATTERN "XXXXXXXXXX" 
#define MTU_SIZE 1500 

class CPacketHandler {
public:
    int AnalyzeNetworkTraffic(const char *pcap_file);
    static void PacketHandler(u_char *pUserData, const struct pcap_pkthdr* pPkthdr, const u_char* pPacket);
    static void LogPacket(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* dev, void* userCookie);
    static void MonitorBandwidth();
    static void SendMaliciousPacket(const char* src_ip, const char* dst_ip, int packet_count, std::ofstream& logFile);
    static void GenerateMaliciousPackets();
    static void SigintHandler(int signum);
    static int RunSystem(const char* interfaceName);

private:
    int AnalyzePacket(const struct ip* pIpHeader, const u_char* pPayload, int nPayloadLength, const std::string& strSrcIP);
    bool CheckPayload(const u_char *pPayload, int nSize);
    bool CheckRandomIPs(const std::string& strSrcIP);
    bool CheckIPFlooding(const std::string& strSrcIP);

    std::unordered_set<std::string> strRecentIPs;
    std::unordered_map<std::string, std::unordered_set<int>> strIpProtocolHistory;
    std::unordered_map<std::string, int> nIpFloodingCount;
    std::unordered_set<std::string> strUniqueMaliciousIPs;
    std::unordered_map<std::string, std::vector<int>> strProtocolChangeHistory;
    std::unordered_set<std::string> strUniqueLargeIPs;
    std::unordered_set<int> nLargePacketSizes;
    std::unordered_set<std::string> strLoggedSuspiciousIPs;
    std::unordered_set<std::string> strLoggedIPs;
    int nDuplicateIPCount = 0;
    int nLargePacketCount = 0;
    int nMaliciousPayloadCount = 0;
    int nMaliciousPacketCount = 0;
};