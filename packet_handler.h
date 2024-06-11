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

#define MAX_PACKET_SIZE 540 
#define PAYLOAD_PATTERN "AAAAAAAAAA" 
#define MTU_SIZE 1500 
#define FLOODING_THRESHOLD 10 // 동일 IP 주소에서 발생하는 과도한 패킷의 임계값
#define RANDOM_IP_THRESHOLD 100 // 무작위 IP 주소를 탐지하기 위한 임계값
#define ABNORMAL_PACKET_RATIO 2 // 비정상 패킷이 정상 패킷보다 몇 배 많은지에 대한 임계값

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

private:
    int AnalyzePacket(const struct ip* pIpHeader, const u_char* pPayload, int nPayloadLength, const std::string& strSrcIP);

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