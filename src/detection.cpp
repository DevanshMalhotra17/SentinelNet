#include "detection.h"
#include <algorithm>

SecurityDetection::SecurityDetection() {
    initializeSuspiciousPorts();
}

void SecurityDetection::initializeSuspiciousPorts() {
    // CRITICAL - Highly dangerous services that should NEVER be exposed
    suspiciousPorts[23] = {ThreatLevel::CRITICAL, "Telnet - Unencrypted remote access"};
    suspiciousPorts[21] = {ThreatLevel::CRITICAL, "FTP - Unencrypted file transfer"};
    suspiciousPorts[69] = {ThreatLevel::CRITICAL, "TFTP - Trivial FTP, no authentication"};
    suspiciousPorts[512] = {ThreatLevel::CRITICAL, "rexec - Remote execution without encryption"};
    suspiciousPorts[513] = {ThreatLevel::CRITICAL, "rlogin - Remote login without encryption"};
    suspiciousPorts[514] = {ThreatLevel::CRITICAL, "rsh - Remote shell without encryption"};
    
    // HIGH - Services commonly exploited or indicate compromise
    suspiciousPorts[3389] = {ThreatLevel::HIGH, "RDP - Remote Desktop (brute-force target)"};
    suspiciousPorts[1433] = {ThreatLevel::HIGH, "MSSQL - Database should not be exposed"};
    suspiciousPorts[3306] = {ThreatLevel::HIGH, "MySQL - Database should not be exposed"};
    suspiciousPorts[5432] = {ThreatLevel::HIGH, "PostgreSQL - Database should not be exposed"};
    suspiciousPorts[27017] = {ThreatLevel::HIGH, "MongoDB - Database should not be exposed"};
    suspiciousPorts[6379] = {ThreatLevel::HIGH, "Redis - Database should not be exposed"};
    suspiciousPorts[5900] = {ThreatLevel::HIGH, "VNC - Remote desktop (often weak auth)"};
    suspiciousPorts[4444] = {ThreatLevel::HIGH, "Metasploit default port - possible backdoor"};
    suspiciousPorts[5555] = {ThreatLevel::HIGH, "Common backdoor/trojan port"};
    suspiciousPorts[1337] = {ThreatLevel::HIGH, "Common hacker/backdoor port"};
    
    // MEDIUM - Services that should be secured or monitored
    suspiciousPorts[22] = {ThreatLevel::MEDIUM, "SSH - Ensure key-based auth and fail2ban"};
    suspiciousPorts[445] = {ThreatLevel::MEDIUM, "SMB - File sharing (vulnerable to attacks)"};
    suspiciousPorts[139] = {ThreatLevel::MEDIUM, "NetBIOS - Old file sharing protocol"};
    suspiciousPorts[135] = {ThreatLevel::MEDIUM, "RPC - Remote Procedure Call"};
    suspiciousPorts[111] = {ThreatLevel::MEDIUM, "RPC - Sun RPC portmapper"};
    suspiciousPorts[2049] = {ThreatLevel::MEDIUM, "NFS - Network File System"};
    suspiciousPorts[161] = {ThreatLevel::MEDIUM, "SNMP - Should use v3 with auth"};
    suspiciousPorts[162] = {ThreatLevel::MEDIUM, "SNMP Trap - Should be secured"};
    suspiciousPorts[1900] = {ThreatLevel::MEDIUM, "UPnP - Can be exploited for DDoS"};
    
    // LOW - Services to monitor but generally OK in homelab
    suspiciousPorts[8080] = {ThreatLevel::LOW, "HTTP-Alt - Common web proxy/admin panel"};
    suspiciousPorts[8443] = {ThreatLevel::LOW, "HTTPS-Alt - Common web admin panel"};
    suspiciousPorts[9090] = {ThreatLevel::LOW, "Admin panel - Verify if intentional"};
}

bool SecurityDetection::isSuspiciousPort(int port, ThreatLevel& level, std::string& reason) {
    auto it = suspiciousPorts.find(port);
    if (it != suspiciousPorts.end()) {
        level = it->second.first;
        reason = it->second.second;
        return true;
    }
    return false;
}

std::vector<SecurityAlert> SecurityDetection::analyzeOpenPorts(
    const std::string& target, 
    const std::vector<int>& openPorts) {
    
    std::vector<SecurityAlert> alerts;
    
    for (int port : openPorts) {
        ThreatLevel level;
        std::string reason;
        
        if (isSuspiciousPort(port, level, reason)) {
            SecurityAlert alert;
            alert.target = target;
            alert.port = port;
            alert.service = reason.substr(0, reason.find(" -"));
            alert.level = level;
            alert.message = reason;
            
            // Generate recommendations based on threat level
            switch (level) {
                case ThreatLevel::CRITICAL:
                    alert.recommendation = "IMMEDIATELY close this port or use VPN/firewall";
                    break;
                case ThreatLevel::HIGH:
                    alert.recommendation = "Close port or restrict access with firewall rules";
                    break;
                case ThreatLevel::MEDIUM:
                    alert.recommendation = "Ensure service is updated and properly secured";
                    break;
                case ThreatLevel::LOW:
                    alert.recommendation = "Monitor service and verify it's intentional";
                    break;
                default:
                    alert.recommendation = "Review service configuration";
            }
            
            alerts.push_back(alert);
        }
    }
    
    // Sort by threat level (highest first)
    std::sort(alerts.begin(), alerts.end(), 
        [](const SecurityAlert& a, const SecurityAlert& b) {
            return a.level > b.level;
        });
    
    return alerts;
}

std::string SecurityDetection::threatLevelToString(ThreatLevel level) {
    switch (level) {
        case ThreatLevel::CRITICAL: return "CRITICAL";
        case ThreatLevel::HIGH: return "HIGH";
        case ThreatLevel::MEDIUM: return "MEDIUM";
        case ThreatLevel::LOW: return "LOW";
        case ThreatLevel::INFO: return "INFO";
        default: return "UNKNOWN";
    }
}

std::string SecurityDetection::getThreatColor(ThreatLevel level) {
    // ANSI color codes for terminal
    switch (level) {
        case ThreatLevel::CRITICAL: return "\033[1;41m"; // Bold Red background
        case ThreatLevel::HIGH: return "\033[1;31m";     // Bold Red
        case ThreatLevel::MEDIUM: return "\033[1;33m";   // Bold Yellow
        case ThreatLevel::LOW: return "\033[1;36m";      // Bold Cyan
        case ThreatLevel::INFO: return "\033[1;37m";     // Bold White
        default: return "\033[0m";                       // Reset
    }
}