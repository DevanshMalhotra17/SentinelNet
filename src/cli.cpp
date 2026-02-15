#include "../include/cli.h"
#include <algorithm>
#include <iostream>
#include <sstream>


CLIOptions CLIParser::parse(int argc, char *argv[]) {
  CLIOptions options;

  for (int i = 1; i < argc; i++) {
    std::string arg = argv[i];

    if (arg == "--help" || arg == "-h") {
      options.showHelp = true;
    } else if (arg == "--target" || arg == "-t") {
      if (i + 1 < argc) {
        options.target = argv[++i];
        if (options.target == "localhost") {
          options.target = "127.0.0.1";
        }
      }
    } else if (arg == "--ports" || arg == "-p") {
      if (i + 1 < argc) {
        options.ports = parsePortList(argv[++i]);
      }
    } else if (arg == "--quick" || arg == "-q") {
      options.quickScan = true;
      options.ports = {21,  22,  23,  25,   80,   135,
                       139, 443, 445, 3306, 3389, 8080};
    } else if (arg == "--full" || arg == "-f") {
      options.fullScan = true;
      for (int port = 1; port <= 1024; port++) {
        options.ports.push_back(port);
      }
    } else if (arg == "--list-interfaces" || arg == "-l") {
      options.listInterfaces = true;
    } else if (arg == "--discover" || arg == "-d") {
      options.discover = true;
      if (i + 1 < argc) {
        options.discoverRange = argv[++i];
      }
    } else if (arg == "--detect-rogue" || arg == "-r") {
      options.detectRogue = true;
    } else if (arg == "--trust") {
      options.trustMode = true;
    } else if (arg == "--list-capture" || arg == "-lc") {
      options.listCaptureInterfaces = true;
    } else if (arg == "--dashboard" || arg == "-D") {
      options.startDashboard = true;
      if (i + 1 < argc) {
        std::string nextArg = argv[i + 1];
        if (!nextArg.empty() && isdigit(nextArg[0])) {
          try {
            options.dashboardPort = std::stoi(nextArg);
            i++;
          } catch (...) {
          }
        }
      }
    }
  }

  return options;
}

std::vector<int> CLIParser::parsePortList(const std::string &portStr) {
  std::vector<int> ports;
  std::stringstream ss(portStr);
  std::string item;

  while (std::getline(ss, item, ',')) {
    try {
      int port = std::stoi(item);
      if (port > 0 && port <= 65535) {
        ports.push_back(port);
      }
    } catch (...) {
      std::cerr << "Warning: Invalid port '" << item << "' ignored."
                << std::endl;
    }
  }

  return ports;
}

void CLIParser::printHelp() {
  std::cout << "\nSentinelNet - Network Security Scanner\n" << std::endl;
  std::cout << "Usage: SentinelNet [options]\n" << std::endl;
  std::cout << "Options:" << std::endl;
  std::cout << "  -h, --help              Show this help message" << std::endl;
  std::cout << "  -l, --list-interfaces   List all network interfaces"
            << std::endl;
  std::cout << "  -lc, --list-capture     List packet capture interfaces"
            << std::endl;
  std::cout << "  -t, --target <IP>       Target IP address to scan"
            << std::endl;
  std::cout
      << "  -p, --ports <ports>     Comma-separated ports (e.g., 80,443,8080)"
      << std::endl;
  std::cout << "  -q, --quick             Quick scan (common ports only)"
            << std::endl;
  std::cout << "  -f, --full              Full scan (ports 1-1024)"
            << std::endl;
  std::cout << "  -d, --discover <range>  Discover devices (CIDR or range)"
            << std::endl;
  std::cout << "  -r, --detect-rogue      Detect unknown/rogue devices"
            << std::endl;
  std::cout
      << "  --trust                 Trust mode (add unknown devices as known)"
      << std::endl;
  std::cout << "  -D, --dashboard [port]  Start web dashboard (default: 8080)"
            << std::endl;
  std::cout << "\nIf no options provided, runs default localhost quick scan.\n"
            << std::endl;
}