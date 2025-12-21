#include "logger.h"
#include <iostream>
#include <filesystem>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace fs = std::filesystem;

logger::logger(const std::string& logDir) : logDirectory(logDir) {
    ensureLogDirectory();
}

void logger::ensureLogDirectory() {
    if (!fs::exists(logDirectory)) {
        fs::create_directory(logDirectory);
        std::cout << "Created log directory: " << logDirectory << std::endl;
    }
}

std::string logger::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

std::string logger::getLogFilename() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    
    std::stringstream ss;
    ss << logDirectory << "/scan_" 
       << std::put_time(std::localtime(&time), "%Y%m%d") 
       << ".log";
    return ss.str();
}

void logger::logScanResult(const std::string& target, 
                          const std::vector<int>& openPorts) {
    std::ofstream logFile(getLogFilename(), std::ios::app);
    
    if (!logFile.is_open()) {
        std::cerr << "Failed to open log file" << std::endl;
        return;
    }
    
    logFile << "[" << getCurrentTimestamp() << "] ";
    logFile << "Port scan: " << target << " | ";
    
    if (openPorts.empty()) {
        logFile << "No open ports found";
    } else {
        logFile << "Open ports: ";
        for (size_t i = 0; i < openPorts.size(); ++i) {
            logFile << openPorts[i];
            if (i < openPorts.size() - 1) {
                logFile << ", ";
            }
        }
    }
    
    logFile << std::endl;
    logFile.close();
}

void logger::logMessage(const std::string& message) {
    std::ofstream logFile(getLogFilename(), std::ios::app);
    
    if (!logFile.is_open()) {
        std::cerr << "Failed to open log file" << std::endl;
        return;
    }
    
    logFile << "[" << getCurrentTimestamp() << "] " << message << std::endl;
    logFile.close();
}