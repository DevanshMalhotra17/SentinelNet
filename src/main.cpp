#include <iostream>
#include <map>
#include <algorithm>
#include "scanner.h"
#include "detection.h"
#include "simulation.h"
#include "server.h"
#include "logger.h"
#include "cli.h"
#include "network_utils.h"
#include "detection.h"
#include "packet_monitor.h"

std::map<int, std::string> getPortServices() {
    return {
        {21, "FTP"},
        {22, "SSH"},
        {23, "Telnet"},
        {25, "SMTP"},
        {80, "HTTP"},
        {135, "RPC"},
        {139, "NetBIOS"},
        {443, "HTTPS"},
        {445, "SMB"},
        {1433, "MS SQL"},
        {3306, "MySQL"},
        {3389, "RDP"},
        {5432, "PostgreSQL"},
        {8080, "HTTP Alt"}
    };
}

void displayScanResults(const std::string& target, const std::vector<int>& openPorts) {
    auto services = getPortServices();
    
    if (openPorts.empty()) {
        std::cout << "No open ports found on " << target << std::endl;
    }
    else {
        std::cout << "\nOpen ports on " << target << ":" << std::endl;
        for (int port : openPorts) {
            std::cout << "  Port " << port;
            if (services.count(port)) {
                std::cout << " (" << services[port] << ")";
            }
            std::cout << " is OPEN" << std::endl;
        }
        std::cout << "\nTotal: " << openPorts.size() << " open port(s)" << std::endl;
    }
}

void testNetworkUtils() {
    std::cout << "\n=== Testing Network Utils ===" << std::endl;
    
    std::cout << "\nIP Conversion Test:" << std::endl;
    uint32_t ip = NetworkUtils::ipToInt("10.0.0.87");
    std::cout << "10.0.0.87 as integer: " << ip << std::endl;
    std::cout << "Back to IP: " << NetworkUtils::intToIp(ip) << std::endl;
    
    std::cout << "\nCIDR Test (10.0.0.0/29 - only 6 IPs):" << std::endl;
    auto cidr_ips = NetworkUtils::expandCIDR("10.0.0.0/29");
    std::cout << "Generated " << cidr_ips.size() << " IPs:" << std::endl;
    for (const auto& ip : cidr_ips) {
        std::cout << "  " << ip << std::endl;
    }
    
    std::cout << "\nRange Test (10.0.0.1-10.0.0.5):" << std::endl;
    auto range_ips = NetworkUtils::expandRange("10.0.0.1-10.0.0.5");
    std::cout << "Generated " << range_ips.size() << " IPs:" << std::endl;
    for (const auto& ip : range_ips) {
        std::cout << "  " << ip << std::endl;
    }
    
    std::cout << "\n=== Tests Complete ===" << std::endl;
}

void performNetworkDiscovery(NetworkScanner& scanner, logger& log, const CLIOptions& options) {
    std::cout << "\n=== Network Discovery ===" << std::endl;
    
    // Expand the range into individual IPs
    std::vector<std::string> targets;
    
    try {
        // Check if it's CIDR notation or IP range
        if (options.discoverRange.find('/') != std::string::npos) {
            // CIDR notation (e.g., 10.0.0.0/24)
            std::cout << "Expanding CIDR range: " << options.discoverRange << std::endl;
            targets = NetworkUtils::expandCIDR(options.discoverRange);
        }
        else if (options.discoverRange.find('-') != std::string::npos) {
            // IP range (e.g., 10.0.0.1-10.0.0.50)
            std::cout << "Expanding IP range: " << options.discoverRange << std::endl;
            targets = NetworkUtils::expandRange(options.discoverRange);
        }
        else {
            std::cerr << "Invalid range format. Use CIDR (10.0.0.0/24) or range (10.0.0.1-10.0.0.50)" << std::endl;
            return;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error parsing range: " << e.what() << std::endl;
        return;
    }
    
    std::cout << "Scanning " << targets.size() << " potential hosts..." << std::endl;
    
    std::cout << "Checking ARP cache for known devices..." << std::endl;
    auto arpHosts = scanner.getArpHosts();
    std::vector<std::string> liveHosts;
    
    if (!arpHosts.empty()) {
        std::cout << "Found " << arpHosts.size() << " device(s) in ARP cache:" << std::endl;
        
        // Filter ARP hosts to only include those in our target range
        for (const auto& arpHost : arpHosts) {
            if (std::find(targets.begin(), targets.end(), arpHost) != targets.end()) {
                liveHosts.push_back(arpHost);
                std::cout << "  [ARP] " << arpHost << std::endl;
            }
        }
    }
    
    // Second pass: Ping remaining hosts not found in ARP
    std::cout << "\nPinging remaining hosts..." << std::endl;
    int checked = 0;
    int remaining = 0;
    
    for (const auto& ip : targets) {
        // Skip if already found in ARP cache
        if (std::find(liveHosts.begin(), liveHosts.end(), ip) != liveHosts.end()) {
            continue;
        }
        
        remaining++;
        checked++;
        
        if (checked % 10 == 0) {
            std::cout << "Progress: " << checked << " hosts pinged..." << std::endl;
        }
        
        if (scanner.isHostAlive(ip, 200)) {
            liveHosts.push_back(ip);
            std::cout << "  [PING] " << ip << std::endl;
        }
    }
    
    std::cout << "\nDiscovery complete: Found " << liveHosts.size() << " live host(s)" << std::endl;
    log.logMessage("Network discovery: " + std::to_string(liveHosts.size()) + " live hosts found in range " + options.discoverRange);
    
    // Third pass: Scan live hosts if ports specified
    if (!options.ports.empty() && !liveHosts.empty()) {
        auto services = getPortServices();
        SecurityDetection detector;
        
        std::cout << "\n=== Scanning Live Hosts ===" << std::endl;
        
        int totalAlerts = 0;
        
        for (const auto& host : liveHosts) {
            std::cout << "\nScanning " << host << "..." << std::endl;
            auto openPorts = scanner.scanPorts(host, options.ports);
            log.logScanResult(host, openPorts);
            
            if (openPorts.empty()) {
                std::cout << "  No open ports found" << std::endl;
            } else {
                // Displays open ports
                for (int port : openPorts) {
                    std::cout << "  Port " << port;
                    if (services.count(port)) {
                        std::cout << " (" << services[port] << ")";
                    }
                    std::cout << " is OPEN" << std::endl;
                }
                
                auto alerts = detector.analyzeOpenPorts(host, openPorts);
                if (!alerts.empty()) {
                    std::cout << "\n  SECURITY ALERTS:" << std::endl;
                    for (const auto& alert : alerts) {
                        std::string color = SecurityDetection::getThreatColor(alert.level);
                        std::string reset = "\033[0m";
                        
                        std::cout << "  " << color << "[" 
                                  << SecurityDetection::threatLevelToString(alert.level) 
                                  << "]" << reset << " Port " << alert.port 
                                  << " - " << alert.message << std::endl;
                        std::cout << "      " << alert.recommendation << std::endl;
                        
                        totalAlerts++;
                        
                        // Logs to file
                        log.logMessage("SECURITY ALERT [" + 
                                     SecurityDetection::threatLevelToString(alert.level) + 
                                     "] " + host + ":" + std::to_string(alert.port) + 
                                     " - " + alert.message);
                    }
                }
            }
        }
        
        if (totalAlerts > 0) {
            std::cout << "\nSecurity Summary: Found " << totalAlerts 
                      << " potential security issue(s)" << std::endl;
            std::cout << "Check sentinelnet.log for details" << std::endl;
        }
    }
    
    else if (liveHosts.empty()) {
        std::cout << "\nNo live hosts found in range." << std::endl;
    }
    
    else {
        std::cout << "\nTip: Add --quick or --ports to scan the discovered hosts." << std::endl;
    }
}


int main(int argc, char* argv[]) {
    if (argc > 1 && std::string(argv[1]) == "--testNU") {
        testNetworkUtils();
        return 0;
    }
    
    NetworkScanner scanner;
    logger log;
    
    log.logMessage("SentinelNet started");
    
    CLIOptions options = CLIParser::parse(argc, argv);
    
    // Show help
    if (options.showHelp) {
        CLIParser::printHelp();
        return 0;
    }
    
    std::cout << "=== SentinelNet Network Scanner ===" << std::endl;
    std::cout << "Hostname: " << scanner.getHostname() << std::endl;
    
    // List interfaces
    if (options.listInterfaces || options.target.empty()) {
        auto interfaces = scanner.getInterfaces();
        std::cout << "\nNetwork Interfaces:" << std::endl;
        for (const auto& i : interfaces) {
            std::cout << "  " << i.name << " | IP: " << i.ip << std::endl;
        }
    }

    // List packet capture interfaces
    if (options.listCaptureInterfaces) {
        std::cout << "\n=== Available Packet Capture Interfaces ===" << std::endl;
        
        PacketMonitor monitor;
        auto captureInterfaces = monitor.listInterfaces();
        
        if (captureInterfaces.empty()) {
            std::cout << "No capture interfaces found!" << std::endl;
            std::cout << "\nTroubleshooting:" << std::endl;
            std::cout << "1. Install Npcap: https://npcap.com" << std::endl;
            std::cout << "2. During installation, check 'WinPcap API-compatible Mode'" << std::endl;
            std::cout << "3. Restart your computer after installation" << std::endl;
        } else {
            std::cout << "Found " << captureInterfaces.size() << " interface(s):\n" << std::endl;
            for (const auto& iface : captureInterfaces) {
                std::cout << "  " << iface << std::endl;
            }
            std::cout << "\nUse the index number [0, 1, 2...] with --monitor" << std::endl;
        }
        
        return 0;
    }

    if (options.discover && !options.discoverRange.empty()) {
        performNetworkDiscovery(scanner, log, options);
        log.logMessage("SentinelNet shutdown");
        return 0;
    }
    
    // Perform scan if target specified
    if (!options.target.empty() && !options.ports.empty()) {
        std::cout << "\nScanning " << options.target << "..." << std::endl;
        
        auto openPorts = scanner.scanPorts(options.target, options.ports);
        log.logScanResult(options.target, openPorts);
        
        displayScanResults(options.target, openPorts);
    }
    else if (options.target.empty() && !options.showHelp && !options.listInterfaces) {
        // Default behavior: quick scan localhost
        std::cout << "\nNo target specified. Running default localhost scan..." << std::endl;
        std::vector<int> defaultPorts = {21, 22, 23, 25, 80, 135, 139, 443, 445, 3306, 3389, 8080};
        
        auto openPorts = scanner.scanPorts("127.0.0.1", defaultPorts);
        log.logScanResult("127.0.0.1", openPorts);
        
        displayScanResults("127.0.0.1", openPorts);
        
        std::cout << "\nTip: Use --help to see all available options." << std::endl;
    }
    
    log.logMessage("SentinelNet shutdown");
    
    return 0;
}