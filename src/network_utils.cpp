#include "network_utils.h"
#include <sstream>
#include <stdexcept>

uint32_t NetworkUtils::ipToInt(const std::string& ip) {
    uint32_t result = 0;
    std::stringstream ss(ip);
    std::string octet;
    int shift = 24;
    
    while (std::getline(ss, octet, '.')) {
        int value = std::stoi(octet);
        if (value < 0 || value > 255) {
            throw std::invalid_argument("Invalid IP address");
        }
        result |= (value << shift);
        shift -= 8;
    }
    
    return result;
}

std::string NetworkUtils::intToIp(uint32_t ip) {
    std::stringstream ss;
    ss << ((ip >> 24) & 0xFF) << "."
       << ((ip >> 16) & 0xFF) << "."
       << ((ip >> 8) & 0xFF) << "."
       << (ip & 0xFF);
    return ss.str();
}