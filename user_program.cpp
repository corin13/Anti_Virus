#include "packet_handler.h"
#include <pcap.h>
#include <vector>
#include <string>
#include <iostream>
#include <atomic>
#include <thread>
#include <chrono>
#include <mutex>

std::mutex print_mutex; // 콘솔 출력을 위한 뮤텍스

std::string selectNetworkInterface() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *d;
    std::vector<std::string> interfaces;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        exit(1);
    }

    for (d = alldevs; d != nullptr; d = d->next) {
        if (d->name) {
            interfaces.push_back(d->name);
        }
    }

    pcap_freealldevs(alldevs);

    if (interfaces.empty()) {
        std::cerr << "No network interfaces found." << std::endl;
        exit(1);
    }

    std::cout << "Available network interfaces:\n";
    for (size_t i = 0; i < interfaces.size(); ++i) {
        std::cout << i + 1 << ". " << interfaces[i] << "\n";
    }

    std::cout << "Select an interface by number: ";
    int choice;
    std::cin >> choice;

    if (choice < 1 || choice > interfaces.size()) {
        std::cerr << "Invalid choice." << std::endl;
        exit(1);
    }

    return interfaces[choice - 1];
}

void displayPacketCount(std::atomic<int>& totalMaliciousPacketsSent, std::atomic<bool>& sendingComplete) {
    while (!sendingComplete.load()) {
        {
            std::lock_guard<std::mutex> lock(print_mutex); // 뮤텍스를 사용하여 동기화
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << "\rTotal packets sent: " << totalMaliciousPacketsSent.load() << std::endl;
    }
}

int SelectInterface() {
    std::string interfaceName = selectNetworkInterface();
    CPacketHandler handler;

    std::atomic<int> totalMaliciousPacketsSent(0);
    std::atomic<bool> sendingComplete(false); // 패킷 전송 완료 플래그

    std::thread packetThread([&]() {
        GenerateMaliciousPackets(totalMaliciousPacketsSent);
        sendingComplete.store(true); // 패킷 전송 완료 플래그 설정
    });

    std::thread displayThread([&]() {
        displayPacketCount(totalMaliciousPacketsSent, sendingComplete);
    });

    packetThread.join();
    displayThread.join(); // displayThread가 종료되도록 변경

    std::lock_guard<std::mutex> lock(print_mutex); // 뮤텍스를 사용하여 동기화
    if (handler.PromptUserForPacketCapture()) {
        handler.CapturePackets(interfaceName.c_str());
        if (handler.PromptUserForPacketAnalysis()) {
            handler.AnalyzeCapturedPackets();
        }
    } else {
        std::cout << "No packets captured." << std::endl;
    }

    return 0;
}