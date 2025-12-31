#pragma once

#include <string>
#include <vector>

class PacketMonitor {
public:
    PacketMonitor();
    ~PacketMonitor();
    
    std::vector<std::string> listInterfaces();

private:
    void* pcapHandle;
};