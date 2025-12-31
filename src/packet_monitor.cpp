#include "packet_monitor.h"
#include <iostream>

// Include pcap
#ifdef _WIN32
    #define HAVE_REMOTE
    #include <pcap.h>
#endif

PacketMonitor::PacketMonitor() : pcapHandle(nullptr) {
}

PacketMonitor::~PacketMonitor() {
}

std::vector<std::string> PacketMonitor::listInterfaces() {
    std::vector<std::string> interfaces;
    
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Find all devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        std::cerr << "Make sure Npcap is installed: https://npcap.com" << std::endl;
        return interfaces;
    }
    
    // Iterate through devices and collect info
    int i = 0;
    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        std::string name = d->name;
        std::string desc = d->description ? d->description : "No description available";
        
        std::string entry = "[" + std::to_string(i) + "] " + name + " - " + desc;
        interfaces.push_back(entry);
        i++;
    }
    
    pcap_freealldevs(alldevs);
    
    return interfaces;
}