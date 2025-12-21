#include <iostream>
#include <vector>
#include <map>
#include "scanner.h"
#include "detection.h"
#include "simulation.h"
#include "server.h"
#include "logger.h"

int main() {
    NetworkScanner scanner;
    DetectionEngine detector;
    AttackSimulator simulator;
    APIServer server;
    logger logger;

    logger.logMessage("SentinelNet started");

    std::cout << "=== SentinelNet Network Scanner ===" << std::endl;
    std::cout << "\nHostname: " << scanner.getHostname() << "\n";
    
    auto interfaces = scanner.getInterfaces();
    std::cout << "\nNetwork Interfaces:\n";
    for (const auto& i : interfaces) {
        std::cout << "  " << i.name << " | IP: " << i.ip << "\n";
    }

    std::map<int, std::string> port_services = {
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

    std::cout << "\n=== Port Scan Demo ===" << std::endl;
    std::cout << "Scanning localhost (127.0.0.1)...\n";
    
    std::vector<int> common_ports = {21, 22, 23, 25, 80, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 8080};
    
    auto open_ports = scanner.scanPorts("127.0.0.1", common_ports);
    logger.logScanResult("127.0.0.1", open_ports);
    
    if (open_ports.empty()) {
        std::cout << "No open ports found on localhost.\n";
    } else {
        std::cout << "Open ports found:\n";
        for (int port : open_ports) {
            std::cout << "  Port " << port;
            if (port_services.count(port)) {
                std::cout << " (" << port_services[port] << ")";
            }
            std::cout << " is OPEN\n";
        }
    }

    std::cout << "\nScanning router (10.0.0.1)...\n";
    auto router_ports = scanner.scanPorts("10.0.0.1", common_ports);
    logger.logScanResult("10.0.0.1", router_ports);
    
    if (router_ports.empty()) {
        std::cout << "No open ports found on router.\n";
    } else {
        std::cout << "Router open ports:\n";
        for (int port : router_ports) {
            std::cout << "  Port " << port << " is OPEN\n";
        }
    }
    
    std::cout << "\n=== Module Status ===" << std::endl;
    auto scan_result = scanner.scan();
    std::cout << "Scanner: " << scan_result << std::endl;

    auto detection_result = detector.analyze(scan_result);
    std::cout << "Detection: " << detection_result << std::endl;

    auto simulation_result = simulator.run();
    std::cout << "Simulation: " << simulation_result << std::endl;

    server.start();
    
    logger.logMessage("SentinelNet shutdown");

    return 0;
}