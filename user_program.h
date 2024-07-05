#pragma once

#include <atomic>
#include <pcap.h>
#include <string>
#include <vector>
#include "error_codes.h"
#include "logfile_manager.h"
#include "packet_generator.h"
#include "packet_handler.h"

class CNetworkInterface{
public:
    std::string SelectNetworkInterface();
    void DisplayPacketCount(std::atomic<int>& nTotalMaliciousPacketsSent, std::atomic<bool>& bSendingComplete);
    int ManageInterface();
};
