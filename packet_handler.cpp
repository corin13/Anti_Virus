#include <arpa/inet.h>
#include <cstring>
#include <fstream>
#include <iostream>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdexcept>
#include "packet_handler.h"

// 패킷 페이로드에 악성 패턴 포함 여부 확인
bool CPacketHandler::CheckPayload(const u_char *pPayload, int nSize) {
    for (int i = 0; i <= nSize - 4; i++) {
        if (memcmp(pPayload + i, PAYLOAD_PATTERN, 4) == 0) {
            return true;
        }
    }
    return false;
}

// IP 주소의 변화가 빈번한지 확인
bool CPacketHandler::CheckRandomIPs(const std::string& strSrcIP) {
    if (strRecentIPs.find(strSrcIP) == strRecentIPs.end()) {
        if (strRecentIPs.size() > 100) {
            strRecentIPs.clear();
        }
        strRecentIPs.insert(strSrcIP);
        return true;
    }
    return false;
}

// 동일한 IP 주소에서 패킷이 과도하게 발생하는지 확인
bool CPacketHandler::CheckIPFlooding(const std::string& strSrcIP) {
    nIpFloodingCount[strSrcIP]++;
    if (nIpFloodingCount[strSrcIP] > 10) { 
        nDuplicateIPCount++;
        return true;
    }
    return false;
}

// 패킷을 분석하여 악성 여부를 판단하고 로그 파일에 기록
int CPacketHandler::AnalyzePacket(const struct ip*  pIpHeader, const u_char* pPayload, int nPayloadLength, const std::string& strSrcIP) {
    bool bIsMalicious = false;

    if (CheckIPFlooding(strSrcIP)) {
        bIsMalicious = true;
        strUniqueMaliciousIPs.insert(strSrcIP);
    }

    // 큰 패킷 확인
    int nIpLength = ntohs(pIpHeader->ip_len);
    if (nIpLength > MAX_PACKET_SIZE) {
        bIsMalicious = true;
        nLargePacketCount++; 
        strUniqueLargeIPs.insert(strSrcIP);  
        nLargePacketSizes.insert(nIpLength); 
    }

    // 프로토콜 변경 확인
    int nProtocol = pIpHeader->ip_p;
    strIpProtocolHistory[strSrcIP].insert(nProtocol);
    if (strIpProtocolHistory[strSrcIP].size() > 3) {
        strProtocolChangeHistory[strSrcIP].assign(strIpProtocolHistory[strSrcIP].begin(), strIpProtocolHistory[strSrcIP].end());
        bIsMalicious = true;
    }

    // UDP 프로토콜의 경우 추가 확인
    if (pIpHeader->ip_p == IPPROTO_UDP) {
        const struct udphdr* pUdpHeader = (struct udphdr*)(pPayload - pIpHeader->ip_hl * 4);
        if (CheckPayload(pPayload, nPayloadLength)) {
            bIsMalicious = true;
            strUniqueMaliciousIPs.insert(strSrcIP);
            nMaliciousPayloadCount++;
        }

        if (CheckRandomIPs(strSrcIP)) {
            std::cout << "Frequent IP change : " << strSrcIP << std::endl;
            bIsMalicious = true;
        }

        int nIpOffset = ntohs(pIpHeader->ip_off);
        if (nIpOffset & IP_MF || (nIpOffset & IP_OFFMASK) != 0) {
            if (CheckPayload(pPayload, nPayloadLength)) {
                std::cout << "Malicious UDP fragmentation payload :" << strSrcIP << " \n" << std::endl;
            } else {
                std::cout << "UDP fragmentation : " << strSrcIP << std::endl;
            }
        }

        int nDstPort = ntohs(pUdpHeader->dest);
        if (nDstPort == UDP_PORT_HTTP) {
            if(strLoggedSuspiciousIPs.find(strSrcIP) == strLoggedSuspiciousIPs.end()){
                std::cout << "Suspicious UDP packet on HTTP port : " << strSrcIP << std::endl;
                strLoggedSuspiciousIPs.insert(strSrcIP);
            }
            bIsMalicious = true;
            strUniqueMaliciousIPs.insert(strSrcIP);
        }
    } else if (pIpHeader->ip_p == IPPROTO_ICMP) {
        if (CheckPayload(pPayload, nPayloadLength)) {
            bIsMalicious = true;
            strUniqueMaliciousIPs.insert(strSrcIP);
            nMaliciousPayloadCount++;
        }

        if (CheckRandomIPs(strSrcIP)) {
            std::cout << "Frequent IP change : " << strSrcIP << std::endl;
            bIsMalicious = true;
        }
    }

    if (bIsMalicious) {
        nMaliciousPacketCount++;

        if(strLoggedIPs.find(strSrcIP) == strLoggedIPs.end()){
            std::ofstream outfile;
            outfile.open("malicious_ips.log", std::ios_base::app);

            if (!outfile.is_open()) {
                return ERROR_CANNOT_OPEN_FILE;
            }
            outfile << strSrcIP << std::endl;
            outfile.close();
            strLoggedIPs.insert(strSrcIP);
        }
    }
    return SUCCESS_CODE;
}

// pcap 패킷 처리 핸들러 함수
void CPacketHandler::PacketHandler(u_char *pUserData, const struct pcap_pkthdr* pPkthdr, const u_char* pPacket) {
    CPacketHandler *pHandler = reinterpret_cast<CPacketHandler*>(pUserData);
    const struct ip* pIpHeader = (struct ip*)(pPacket + 14);
    int nIpHeaderLength = pIpHeader->ip_hl * 4;
    int nIpTotalLength = ntohs(pIpHeader->ip_len);
    int nPayloadLength = nIpTotalLength - nIpHeaderLength;
    const u_char* pPayload = pPacket + 14 + nIpHeaderLength;
    std::string strSrcIP = inet_ntoa(pIpHeader->ip_src);

    pHandler->AnalyzePacket(pIpHeader, pPayload, nPayloadLength, strSrcIP);
}

// pcap 파일을 분석하여 네트워크 트래픽을 처리하고, 이상 현상을 감지
int CPacketHandler::AnalyzeNetworkTraffic(const char *pcap_file) {

    char chErrbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pHandle = pcap_open_offline(pcap_file, chErrbuf);
    if (!pHandle) {
        return ERROR_CANNOT_OPEN_FILE;
    }

    char chFilterExp[] = "ip";
    struct bpf_program fp;
    if (pcap_compile(pHandle, &fp, chFilterExp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        pcap_close(pHandle);
        return ERROR_INVALID_OPTION;
    }

    if (pcap_setfilter(pHandle, &fp) == -1) {
        pcap_close(pHandle);
        return ERROR_INVALID_OPTION;
    }

    CPacketHandler handler;
    try{
        pcap_loop(pHandle, 0, PacketHandler, reinterpret_cast<u_char*>(&handler));
    } catch(...){
        pcap_close(pHandle);
        return ERROR_UNKNOWN;
    }
    pcap_close(pHandle);

    std::cout << COLOR_YELLOW "\n******************************************* WARNING *******************************************\n\n" << COLOR_RESET;
    std::cout << COLOR_WHITE "## Random protocol changes : ";

    if (handler.strProtocolChangeHistory.empty()) {
        std::cout << COLOR_RED "No random protocol changes detected." << COLOR_RESET << std::endl;
    } else {
        for (const auto& entry : handler.strProtocolChangeHistory) {
            std::cout << COLOR_RED "IP " << entry.first << " - Protocols: ";
            for (const auto& proto : entry.second) {
                std::cout << proto << " ";
            }
            std::cout << COLOR_RESET << std::endl;
        }
    }

    std::cout << COLOR_WHITE "## Total duplicate IP : " << COLOR_RED << handler.nDuplicateIPCount << COLOR_RESET << std::endl;
    std::cout << COLOR_WHITE "## Total large packets : " << COLOR_RED << handler.nLargePacketCount << COLOR_RESET << std::endl;
    std::cout << COLOR_WHITE "## Large packet sizes : " << COLOR_RED;

    for (const auto& size : handler.nLargePacketSizes) {
        std::cout << size << " ";
    }
    
    std::cout << COLOR_RESET << std::endl;
    std::cout << COLOR_WHITE "## Total malicious payloads : " << COLOR_RED << handler.nMaliciousPayloadCount << COLOR_RESET << " (Pattern: " << PAYLOAD_PATTERN << ")\n" << std::endl;
    std::cout << COLOR_WHITE "## Total malicious packets detected : " << COLOR_RED << handler.nMaliciousPacketCount << COLOR_RESET << std::endl;

    return SUCCESS_CODE;
}