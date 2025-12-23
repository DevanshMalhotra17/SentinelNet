#include <iostream>
#include <map>
#include "scanner.h"
#include "detection.h"
#include "simulation.h"
#include "server.h"
#include "logger.h"
#include "cli.h"
#include "network_utils.h"

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
    } else {
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