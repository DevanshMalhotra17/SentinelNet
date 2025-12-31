# pragma once

#include <string>
#include <vector>
#include <map>

enum class ThreatLevel {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

struct SecurityAlert {
    std::string target;
    int port;
    std::string service;
    ThreatLevel level;
    std::string message;
    std::string recommendation;
};

class SecurityDetection {
public:
    SecurityDetection();
    
    // Analyzes open ports and returns security alerts
    std::vector<SecurityAlert> analyzeOpenPorts(const std::string& target, const std::vector<int>& openPorts);
    
    // Checks if a port is suspicious
    bool isSuspiciousPort(int port, ThreatLevel& level, std::string& reason);
    
    // Gets threat level as a string
    static std::string threatLevelToString(ThreatLevel level);
    
    // Gets color code for terminal output
    static std::string getThreatColor(ThreatLevel level);

private:
    // Database of suspicious ports and their threat levels
    std::map<int, std::pair<ThreatLevel, std::string>> suspiciousPorts;
    
    void initializeSuspiciousPorts();
};