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

// 사용 가능한 네트워크 인터페이스 목록을 사용자에게 제공하는 함수
std::string CNetworkInterface::SelectNetworkInterface() {
    char chErrBuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *pAlldevs, *pDevice;
    std::vector<std::string> strInterfaces;

    if (pcap_findalldevs(&pAlldevs, chErrBuf) == -1) return GetErrorMessage(ERROR_CANNOT_OPEN_DEVICE);

    for (pDevice = pAlldevs; pDevice != nullptr; pDevice = pDevice->next) {
        if (pDevice->name) strInterfaces.push_back(pDevice->name);
    }

    pcap_freealldevs(pAlldevs);
    if (strInterfaces.empty()) return GetErrorMessage(ERROR_CANNOT_FIND_INTERFACE);
    
    std::cout << "\n[Available network interfaces]\n";
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

// 패킷 전송이 완료될 때까지 대기하며, 전송된 패킷의 총 개수를 출력하는 함수
void CNetworkInterface::DisplayPacketCount(std::atomic<int>& nTotalMaliciousPacketsSent, std::atomic<bool>& bSendingComplete) {
    try {
        while (!bSendingComplete.load()) {
            {
                std::lock_guard<std::mutex> lock(print_mutex);
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        {
            std::lock_guard<std::mutex> lock(print_mutex);
            std::cout << "\rTotal number of packets sent: " << nTotalMaliciousPacketsSent.load() << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error during packet count display: " << e.what() << std::endl;
    }
}

// 네트워크 인터페이스를 선택하고, 해당 인터페이스에서 패킷을 캡처하고 분석하는 과정을 관리하는 함수
int CNetworkInterface::ManageInterface() {
    if (CLoggingManager::StartRotation() != SUCCESS_CODE ||
        CLoggingManager::GenerateLogs("packetLogger") != SUCCESS_CODE ||
        CLoggingManager::RotateLogs() != SUCCESS_CODE) {
        std::cerr << "Log operation failed." << std::endl;
        return ERROR_LOG_OPERATION_FAILED;
    }

    int nChoice;
    std::cout << "\n[Select an option]\n";
    std::cout << "1. Generate and capture packets in real-time\n";
    std::cout << "2. Analyze existing pcap file\n";
    std::cout << "\n## Enter your choice: ";
    std::cin >> nChoice;

    if (nChoice == 1) {
        std::string strInterfaceName = SelectNetworkInterface();
        if (strInterfaceName.empty()) return ERROR_CANNOT_OPEN_DEVICE;

        CPacketHandler handler;
        CPacketGenerator packetGenerator;

        std::atomic<int> nTotalMaliciousPacketsSent(0);
        std::atomic<bool> bSendingComplete(false);

        std::thread packetThread([&]() {
            packetGenerator.GenerateMaliciousPackets(nTotalMaliciousPacketsSent);
            bSendingComplete.store(true);
        });

        std::thread displayThread([&]() {
            DisplayPacketCount(nTotalMaliciousPacketsSent, bSendingComplete);
        });

        packetThread.join();
        displayThread.join();

        std::lock_guard<std::mutex> lock(print_mutex);
        if (handler.PromptUserForPacketCapture()) {
            handler.CapturePackets(strInterfaceName.c_str());
            if (handler.PromptUserForPacketAnalysis()) handler.AnalyzeCapturedPackets();
        } else {
            std::cout << "No packets captured." << std::endl;
        }
    } else if (nChoice == 2) {
        std::string strPcapFilePath;
        std::cout << "\n## Enter the pcap file path (ex. packets/packet1.pcap): ";
        std::cin >> strPcapFilePath;

        CPacketHandler handler;
        auto result = handler.AnalyzeNetworkTraffic(strPcapFilePath.c_str());
        if (result == SUCCESS_CODE) {
            std::cout << COLOR_GREEN "\nPacket analysis completed successfully." << COLOR_RESET << std::endl;
        } else {
            std::cerr << "Packet analysis failed with error code: " << result << std::endl;
        }
        std::cout << COLOR_RED "Number of malicious packets detected: " << handler.m_DetectionCount << COLOR_RESET << std::endl;
    } else {
        std::cerr << "Invalid choice." << std::endl;
        return ERROR_INVALID_CHOICE;
    }
    return SUCCESS_CODE;
}