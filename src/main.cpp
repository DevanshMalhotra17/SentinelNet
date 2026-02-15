#include "cli.h"
#include "detection.h"
#include "logger.h"
#include "network_utils.h"
#include "packet_monitor.h"
#include "scanner.h"
#include "server.h"
#include <algorithm>
#include <iostream>
#include <map>
#include <sstream>
#include <vector>

std::map<int, std::string> getPortServices() {
  return {{21, "FTP"},          {22, "SSH"},       {23, "Telnet"},
          {25, "SMTP"},         {80, "HTTP"},      {135, "RPC"},
          {139, "NetBIOS"},     {443, "HTTPS"},    {445, "SMB"},
          {1433, "MS SQL"},     {3306, "MySQL"},   {3389, "RDP"},
          {5432, "PostgreSQL"}, {5433, "HTTP Alt"}};
}

void displayScanResults(const std::string &target,
                        const std::vector<int> &openPorts) {
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
    std::cout << "\nTotal: " << openPorts.size() << " open port(s)"
              << std::endl;
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
  for (const auto &ip : cidr_ips) {
    std::cout << "  " << ip << std::endl;
  }

  std::cout << "\nRange Test (10.0.0.1-10.0.0.5):" << std::endl;
  auto range_ips = NetworkUtils::expandRange("10.0.0.1-10.0.0.5");
  std::cout << "Generated " << range_ips.size() << " IPs:" << std::endl;
  for (const auto &ip : range_ips) {
    std::cout << "  " << ip << std::endl;
  }

  std::cout << "\n=== Tests Complete ===" << std::endl;
}

void performNetworkDiscovery(NetworkScanner &scanner, logger &log,
                             const CLIOptions &options) {
  std::cout << "\n=== Network Discovery ===" << std::endl;

  // Expand the range into individual IPs
  std::vector<std::string> targets;

  try {
    // Check if it's CIDR notation or IP range
    if (options.discoverRange.find('/') != std::string::npos) {
      // CIDR notation (e.g., 10.0.0.0/24)
      std::cout << "Expanding CIDR range: " << options.discoverRange
                << std::endl;
      targets = NetworkUtils::expandCIDR(options.discoverRange);
    } else if (options.discoverRange.find('-') != std::string::npos) {
      // IP range (e.g., 10.0.0.1-10.0.0.50)
      std::cout << "Expanding IP range: " << options.discoverRange << std::endl;
      targets = NetworkUtils::expandRange(options.discoverRange);
    } else {
      std::cerr << "Invalid range format. Use CIDR (10.0.0.0/24) or range "
                   "(10.0.0.1-10.0.0.50)"
                << std::endl;
      return;
    }
  } catch (const std::exception &e) {
    std::cerr << "Error parsing range: " << e.what() << std::endl;
    return;
  }

  std::cout << "Scanning " << targets.size() << " potential hosts..."
            << std::endl;
  std::cout << "This may take 30-60 seconds...\n" << std::endl;

  std::vector<std::string> liveHosts;
  int checked = 0;

  // Ping all hosts in range
  for (const auto &ip : targets) {
    checked++;

    if (checked % 25 == 0) {
      std::cout << "Progress: " << checked << "/" << targets.size()
                << " checked..." << std::endl;
    }

    if (scanner.isHostAlive(ip, 200)) {
      liveHosts.push_back(ip);
      std::cout << "  [FOUND] " << ip << std::endl;
    }
  }

  std::cout << "\nDiscovery complete: Found " << liveHosts.size()
            << " live device(s)" << std::endl;

  log.logMessage("Network discovery: " + std::to_string(liveHosts.size()) +
                 " live hosts found in range " + options.discoverRange);

  // Scan live hosts if ports specified
  if (!options.ports.empty() && !liveHosts.empty()) {
    auto services = getPortServices();
    SecurityDetection detector;

    std::cout << "\n=== Scanning Live Devices ===" << std::endl;

    int totalAlerts = 0;

    for (const auto &host : liveHosts) {
      std::cout << "\nScanning " << host << "..." << std::endl;
      auto openPorts = scanner.scanPorts(host, options.ports);
      log.logScanResult(host, openPorts);

      if (openPorts.empty()) {
        std::cout << "  No open ports found" << std::endl;
      } else {
        // Display open ports
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
          for (const auto &alert : alerts) {
            std::string color = SecurityDetection::getThreatColor(alert.level);
            std::string reset = "\033[0m";

            std::cout << "  " << color << "["
                      << SecurityDetection::threatLevelToString(alert.level)
                      << "]" << reset << " Port " << alert.port << " - "
                      << alert.message << std::endl;
            std::cout << "      " << alert.recommendation << std::endl;

            totalAlerts++;

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
      std::cout << "Check logs for details" << std::endl;
    }
  }

  else if (liveHosts.empty()) {
    std::cout << "\nNo live devices found in range." << std::endl;
  }

  else {
    std::cout << "\nTip: Add --quick or --ports to scan the discovered devices."
              << std::endl;
  }
}

void runScanner(const CLIOptions &options, NetworkScanner &scanner,
                logger &log) {
  // Show help
  if (options.showHelp) {
    CLIParser::printHelp();
    return;
  }

  // List interfaces
  if (options.listInterfaces) {
    auto interfaces = scanner.getInterfaces();
    std::cout << "\nNetwork Interfaces:" << std::endl;
    for (const auto &i : interfaces) {
      std::cout << "  " << i.name << " | IP: " << i.ip << std::endl;
    }
    // REMOVED return here to allow flow to scan
  }

  // NEW: Start web dashboard
  if (options.startDashboard) {
    std::cout << "\n=== Starting Web Dashboard ===" << std::endl;
    std::cout << "Open your browser to http://localhost:"
              << options.dashboardPort << std::endl;
    std::cout << "Press Ctrl+C to stop\n" << std::endl;
    APIServer server(options.dashboardPort);
    log.logMessage("Web dashboard started on port " +
                   std::to_string(options.dashboardPort));
    server.start();
    return;
  }

  if (options.discover && !options.discoverRange.empty()) {
    performNetworkDiscovery(scanner, log, options);
    return;
  }

  // Perform scan if target specified
  if (!options.target.empty() && !options.ports.empty()) {
    std::cout << "Scanning " << options.target << "..." << std::endl;

    auto openPorts = scanner.scanPorts(options.target, options.ports);
    log.logScanResult(options.target, openPorts);

    displayScanResults(options.target, openPorts);
  } else {
    // Default localhost scan
    std::cout << "No target specified. Running default localhost scan..."
              << std::endl;
    std::string defaultTarget = "127.0.0.1";
    std::vector<int> defaultPorts = {21,  22,  23,  25,   80,   135,
                                     139, 443, 445, 3306, 3389, 8080};

    auto openPorts = scanner.scanPorts(defaultTarget, defaultPorts);
    log.logScanResult(defaultTarget, openPorts);
    displayScanResults(defaultTarget, openPorts);
  }
}

int main(int argc, char *argv[]) {
  NetworkScanner scanner;
  logger log;

  log.logMessage("SentinelNet started");

  if (argc > 1) {
    // CLI Mode: Process arguments and exit
    if (std::string(argv[1]) == "--testNU") {
      testNetworkUtils();
      return 0;
    }

    CLIOptions options = CLIParser::parse(argc, argv);
    runScanner(options, scanner, log);
  } else {
    // Shell Mode: Interactive loop
    std::cout << "\n=== SentinelNet Shell v2.0 ===" << std::endl;
    std::cout << "Type '-h' or '--help' to see available commands."
              << std::endl;
    std::cout << "Type 'exit' or 'quit' to close." << std::endl;

    std::string input;
    while (true) {
      std::cout << "\nSentinelNet> ";
      if (!std::getline(std::cin, input) || input == "exit" ||
          input == "quit") {
        break;
      }

      if (input.empty())
        continue;

      // Tokenize input for the parser
      std::stringstream ss(input);
      std::string token;
      std::vector<char *> args;

      // Dummy argv[0]
      char progName[] = "SentinelNet";
      args.push_back(progName);

      std::vector<std::string> tokens;
      while (ss >> token) {
        tokens.push_back(token);
      }

      for (auto &t : tokens) {
        args.push_back(const_cast<char *>(t.c_str()));
      }

      CLIOptions options =
          CLIParser::parse(static_cast<int>(args.size()), args.data());
      runScanner(options, scanner, log);
    }
  }

  log.logMessage("SentinelNet shutdown");
  return 0;
}
