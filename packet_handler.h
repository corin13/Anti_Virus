#pragma once

#include <netinet/ip.h>
#include <pcap.h>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include "ansi_color.h"
#include "error_codes.h"

#define MAX_PACKET_SIZE 1000
#define UDP_PORT_HTTP 80
#define PAYLOAD_PATTERN "XXXXXXXXXXXXXXXX"
#define MTU_SIZE 1500

class CPacketHandler {
public:
    int nMaliciousPacketCount = 0;
    int nLargePacketCount = 0;
    int nDuplicateIPCount = 0;
    int nMaliciousPayloadCount = 0;
    std::set<int> nLargePacketSizes;
    std::unordered_set<std::string> strUniqueMaliciousIPs;
    std::unordered_set<std::string> strUniqueLargeIPs;
    std::unordered_set<std::string> strRecentIPs;
    std::unordered_set<std::string> strLoggedIPs;
    std::unordered_map<std::string, int> nIpFloodingCount;
    std::unordered_set<std::string> strLoggedSuspiciousIPs;
    std::unordered_map<std::string, std::unordered_set<int>> strIpProtocolHistory;
    std::unordered_map<std::string, std::vector<int>> strProtocolChangeHistory;

    int AnalyzePacket(const struct ip* pIpHeader, const u_char* pPayload, int nPayloadLength, const std::string& strSrcIP);
    static void PacketHandler(u_char *pUserData, const struct pcap_pkthdr* pPkthdr, const u_char* pPacket);
    static int AnalyzeNetworkTraffic(const char *pcap_file);

private:
    bool CheckPayload(const u_char *pPayload, int nSize);
    bool CheckRandomIPs(const std::string& strSrcIP);
    bool CheckIPFlooding(const std::string& strSrcIP);
};