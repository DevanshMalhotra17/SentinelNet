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
};

class CLIParser {
public:
    static CLIOptions parse(int argc, char* argv[]);
    static void printHelp();
    static std::vector<int> parsePortList(const std::string& portStr);
};