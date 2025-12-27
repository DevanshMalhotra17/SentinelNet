#pragma once

#include <string>
#include <vector>

struct NetworkInterface {
    std::string name;
    std::string ip;
};

class NetworkScanner {
public:
    NetworkScanner();

    std::string getHostname() const;
    std::vector<NetworkInterface> getInterfaces() const;

    std::string scan() const;
    
    std::vector<int> scanPorts(const std::string& target, const std::vector<int>& ports) const;
    
    bool isHostAlive(const std::string& target, int timeoutMs = 500) const;
};