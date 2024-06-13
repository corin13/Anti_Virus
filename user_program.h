#pragma once

#include <pcap.h>
#include <vector>
#include <string>
#include <atomic>
#include "packet_generator.h"
#include "packet_handler.h"

class CNetworkInterface{
public:
    std::string SelectNetworkInterface();
    void DisplayPacketCount(std::atomic<int>& totalMaliciousPacketsSent, std::atomic<bool>& sendingComplete);
    int SelectInterface();
};
