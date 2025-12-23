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

std::vector<std::string> NetworkUtils::expandCIDR(const std::string& cidr) {
    std::vector<std::string> ips;
    
    size_t slashPos = cidr.find('/');
    if (slashPos == std::string::npos) {
        throw std::invalid_argument("Invalid CIDR notation");
    }
    
    std::string baseIp = cidr.substr(0, slashPos);
    int prefixLength = std::stoi(cidr.substr(slashPos + 1));
    
    if (prefixLength < 0 || prefixLength > 32) {
        throw std::invalid_argument("Invalid prefix length");
    }
    
    uint32_t base = ipToInt(baseIp);
    uint32_t mask = (0xFFFFFFFF << (32 - prefixLength)) & 0xFFFFFFFF;
    uint32_t network = base & mask;
    uint32_t hostMask = ~mask;
    
    for (uint32_t host = 1; host < hostMask; host++) {
        ips.push_back(intToIp(network | host));
    }
    
    return ips;
}

std::vector<std::string> NetworkUtils::expandRange(const std::string& range) {
    std::vector<std::string> ips;
    
    size_t dashPos = range.find('-');
    if (dashPos == std::string::npos) {
        throw std::invalid_argument("Invalid range format");
    }
    
    std::string startIp = range.substr(0, dashPos);
    std::string endIp = range.substr(dashPos + 1);
    
    uint32_t start = ipToInt(startIp);
    uint32_t end = ipToInt(endIp);
    
    if (start > end) {
        throw std::invalid_argument("Start IP must be less than end IP");
    }
    
    for (uint32_t ip = start; ip <= end; ip++) {
        ips.push_back(intToIp(ip));
    }
    
    return ips;
}