#include <iostream>
#include <map>
#include "scanner.h"
#include "detection.h"
#include "simulation.h"
#include "server.h"
#include "logger.h"
#include "cli.h"

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

int main(int argc, char* argv[]) {
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