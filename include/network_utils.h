#pragma once

#include <string>
#include <vector>
#include <cstdint>

class NetworkUtils {
public:
    static uint32_t ipToInt(const std::string& ip);
    
    static std::string intToIp(uint32_t ip);
};