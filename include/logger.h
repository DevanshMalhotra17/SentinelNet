#pragma once

#include <string>
#include <vector>
#include <fstream>

class logger {
public:
    logger(const std::string& logDir = "logs");
    
    void logScanResult(const std::string& target, const std::vector<int>& openPorts);
    
    void logMessage(const std::string& message);
    
private:
    std::string logDirectory;
    std::string getCurrentTimestamp() const;
    std::string getLogFilename() const;
    void ensureLogDirectory();
};