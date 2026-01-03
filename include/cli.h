#pragma once

#include <string>
#include <vector>

struct CLIOptions {
    std::string target = "";
    std::vector<int> ports;
    bool quickScan = false;
    bool fullScan = false;
    bool showHelp = false;
    bool listInterfaces = false;
    bool discover = false;
    std::string discoverRange = "";
    bool detectRogue = false;
    bool trustMode = false;
    bool listCaptureInterfaces = false;
    bool startDashboard = false;
    int dashboardPort = 8080;
};

class CLIParser {
public:
    static CLIOptions parse(int argc, char* argv[]);
    static void printHelp();
    static std::vector<int> parsePortList(const std::string& portStr);
};