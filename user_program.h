#pragma once

#include <pcap.h>
#include <vector>
#include <string>
#include <atomic>
#include "packet_generator.h"
#include "packet_handler.h"

std::string selectNetworkInterface();
void displayPacketCount(std::atomic<int>& totalMaliciousPacketsSent);
int SelectInterface();