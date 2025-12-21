#include <iostream>
#include "scanner.h"
#include "detection.h"
#include "simulation.h"
#include "server.h"

int main() {
    NetworkScanner scanner;
    DetectionEngine detector;
    AttackSimulator simulator;
    APIServer server;

    std::cout << "Hostname: " << scanner.getHostname() << "\n";
    auto interfaces = scanner.getInterfaces();
    for (const auto& i : interfaces) {
        std::cout << "Interface: " << i.name << " | IP: " << i.ip << "\n";
    }

    auto scan_result = scanner.scan();
    std::cout << "Scanner: " << scan_result << std::endl;

    auto detection_result = detector.analyze(scan_result);
    std::cout << "Detection: " << detection_result << std::endl;

    auto simulation_result = simulator.run();
    std::cout << "Simulation: " << simulation_result << std::endl;

    server.start();

    return 0;
}