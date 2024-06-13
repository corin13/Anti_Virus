#include <atomic>
#include <chrono>
#include <iostream>
#include <mutex>
#include <pcap.h>
#include <string>
#include <thread>
#include <vector>
#include "user_program.h"

std::mutex print_mutex;

std::string CNetworkInterface::SelectNetworkInterface() {
    char chErrBuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *pAlldevs, *pDevice;
    std::vector<std::string> strInterfaces;

    if (pcap_findalldevs(&pAlldevs, chErrBuf) == -1) {
        return GetErrorMessage(ERROR_CANNOT_OPEN_DEVICE);
    }
    for (pDevice = pAlldevs; pDevice != nullptr; pDevice = pDevice->next) {
        if (pDevice->name) {
            strInterfaces.push_back(pDevice->name);
        }
    }

    pcap_freealldevs(pAlldevs);
    if (strInterfaces.empty()) {
        return GetErrorMessage(ERROR_CANNOT_FIND_INTERFACE);
    }

    std::cout << "\nAvailable network interfaces:\n";
    for (size_t siIndex = 0; siIndex < strInterfaces.size(); ++siIndex) {
        std::cout << siIndex + 1 << ". " << strInterfaces[siIndex] << "\n";
    }

    std::cout << "\n## Select an interface by number: ";
    size_t siChoice;
    std::cin >> siChoice;
    if (siChoice < 1 || siChoice > strInterfaces.size()) {
        std::cerr << GetErrorMessage(ERROR_INVALID_CHOICE) << std::endl;
        return GetErrorMessage(ERROR_INVALID_CHOICE);
    }
    return strInterfaces[siChoice - 1];
}

void CNetworkInterface::DisplayPacketCount(std::atomic<int>& totalMaliciousPacketsSent, std::atomic<bool>& sendingComplete) {
    try {
        while (!sendingComplete.load()) {
            {
                std::lock_guard<std::mutex> lock(print_mutex);
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        {
            std::lock_guard<std::mutex> lock(print_mutex);
            std::cout << "\rTotal number of packets sent: " << totalMaliciousPacketsSent.load() << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error during packet count display: " << e.what() << std::endl;
    }
}

int CNetworkInterface::SelectInterface() {
    if (CLoggingManager::StartRotation() != SUCCESS_CODE ||
        CLoggingManager::GenerateLogs("packetLogger") != SUCCESS_CODE ||
        CLoggingManager::RotateLogs() != SUCCESS_CODE) {
        std::cerr << "Log operation failed." << std::endl;
        return ERROR_LOG_OPERATION_FAILED;
    }

    std::string strInterfaceName = SelectNetworkInterface();
    if (strInterfaceName.empty()) {
        return ERROR_CANNOT_OPEN_DEVICE;
    }

    CPacketHandler handler;
    CPacketGenerator packetGenerator;

    std::atomic<int> totalMaliciousPacketsSent(0);
    std::atomic<bool> sendingComplete(false);

    std::thread packetThread([&]() {
        packetGenerator.GenerateMaliciousPackets(totalMaliciousPacketsSent);
        sendingComplete.store(true);
    });

    std::thread displayThread([&]() {
        DisplayPacketCount(totalMaliciousPacketsSent, sendingComplete);
    });

    packetThread.join();
    displayThread.join();

    std::lock_guard<std::mutex> lock(print_mutex);
    if (handler.PromptUserForPacketCapture()) {
        handler.CapturePackets(strInterfaceName.c_str());
        if (handler.PromptUserForPacketAnalysis()) {
            handler.AnalyzeCapturedPackets();
        }
    } else {
        std::cout << "No packets captured." << std::endl;
    }
    return SUCCESS_CODE;
}