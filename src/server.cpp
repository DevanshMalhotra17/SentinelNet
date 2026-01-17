#include "server.h"
#include "scanner.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <mutex>
#include <ctime>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#endif

// Store scan results
struct ScanData {
    std::string ip;
    std::vector<int> ports;
    std::string timestamp;
};

std::vector<ScanData> scanResults;
std::mutex dataMutex;

APIServer::APIServer(int port) : serverPort(port), isRunning(false) {
}

APIServer::~APIServer() {
    stop();
}

std::string readFile(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        return "";
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

std::string getCurrentTime() {
    time_t now = time(nullptr);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    return std::string(buf);
}

std::string buildScansJSON() {
    std::lock_guard<std::mutex> lock(dataMutex);
    
    std::string json = "{\"scans\":[";
    for (size_t i = 0; i < scanResults.size(); i++) {
        json += "{";
        json += "\"ip\":\"" + scanResults[i].ip + "\",";
        json += "\"timestamp\":\"" + scanResults[i].timestamp + "\",";
        json += "\"ports\":[";
        for (size_t j = 0; j < scanResults[i].ports.size(); j++) {
            json += std::to_string(scanResults[i].ports[j]);
            if (j < scanResults[i].ports.size() - 1) json += ",";
        }
        json += "]}";
        if (i < scanResults.size() - 1) json += ",";
    }
    json += "]}";
    
    return json;
}

void APIServer::start() {
    std::cout << "\n=== SentinelNet Dashboard Starting ===" << std::endl;
    std::cout << "Open browser: http://localhost:" << serverPort << std::endl;
    std::cout << "Press Ctrl+C to stop\n" << std::endl;
    
    // Log initial state
    std::cout << "Initial scan results: " << scanResults.size() << std::endl;
    
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    
    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "Failed to create socket" << std::endl;
        return;
    }
    
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(serverPort);
    
    if (bind(serverSocket, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed. Port " << serverPort << " may be in use." << std::endl;
        closesocket(serverSocket);
        return;
    }
    
    if (listen(serverSocket, 5) == SOCKET_ERROR) {
        std::cerr << "Listen failed" << std::endl;
        closesocket(serverSocket);
        return;
    }
    
    std::cout << "Server listening on port " << serverPort << "..." << std::endl;
    
    isRunning = true;
    
    while (isRunning) {
        SOCKET clientSocket = accept(serverSocket, nullptr, nullptr);
        if (clientSocket == INVALID_SOCKET) continue;
        
        char buffer[4096] = {0};
        recv(clientSocket, buffer, sizeof(buffer), 0);
        
        std::string request(buffer);
        std::string response;
        
        std::cout << "[REQUEST] " << request.substr(0, request.find("\r\n")) << std::endl;
        
        if (request.find("GET / ") != std::string::npos || 
            request.find("GET /dashboard.html") != std::string::npos) {
            std::string html = readFile("index.html");
            if (html.empty()) html = readFile("dashboard.html");
            if (html.empty()) html = readFile("../web/dashboard.html");
            if (html.empty()) html = readFile("../web/index.html");
            
            if (html.empty()) {
                response = "HTTP/1.1 404 Not Found\r\n\r\n404 - HTML file not found";
            } else {
                response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + html;
            }
        }
        else if (request.find("GET /style.css") != std::string::npos) {
            std::string css = readFile("style.css");
            if (css.empty()) css = readFile("../web/style.css");
            response = "HTTP/1.1 200 OK\r\nContent-Type: text/css\r\n\r\n" + css;
        }
        else if (request.find("GET /script.js") != std::string::npos) {
            std::string js = readFile("script.js");
            if (js.empty()) js = readFile("../web/script.js");
            response = "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n" + js;
        }
        else if (request.find("GET /api/scans") != std::string::npos) {
            std::string json = buildScansJSON();
            response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n" + json;
        }
        else if (request.find("GET /api/alerts") != std::string::npos) {
            response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n{\"alerts\":[]}";
        }
        else if (request.find("POST /api/scan/trigger") != std::string::npos) {
            std::cout << "[API] Scan trigger received" << std::endl;
            
            // Parse body for target IP
            size_t bodyStart = request.find("\r\n\r\n");
            std::string target = "127.0.0.1";
            
            if (bodyStart != std::string::npos) {
                std::string body = request.substr(bodyStart + 4);
                std::cout << "[DEBUG] Body: " << body << std::endl;
                
                // Simple JSON parsing for target
                size_t targetPos = body.find("\"target\"");
                if (targetPos != std::string::npos) {
                    size_t start = body.find("\"", targetPos + 8);
                    size_t end = body.find("\"", start + 1);
                    if (start != std::string::npos && end != std::string::npos) {
                        target = body.substr(start + 1, end - start - 1);
                    }
                }
            }
            
            std::cout << "[SCAN] Starting scan of " << target << std::endl;
            
            // Perform actual scan
            NetworkScanner scanner;
            std::vector<int> commonPorts = {21, 22, 23, 25, 80, 135, 139, 443, 445, 3306, 3389, 8080};
            std::vector<int> openPorts = scanner.scanPorts(target, commonPorts);
            
            // Store results
            {
                std::lock_guard<std::mutex> lock(dataMutex);
                ScanData data;
                data.ip = target;
                data.ports = openPorts;
                data.timestamp = getCurrentTime();
                scanResults.push_back(data);
                
                std::cout << "[DATA] Added scan result: " << target 
                          << " (" << openPorts.size() << " ports)" << std::endl;
            }
            
            std::cout << "[SCAN] Completed scan of " << target 
                      << " - " << openPorts.size() << " ports open" << std::endl;
            
            response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n{\"status\":\"success\"}";
        }
        else if (request.find("POST /api/clear") != std::string::npos) {
            std::lock_guard<std::mutex> lock(dataMutex);
            scanResults.clear();
            std::cout << "[DATA] Cleared all scan results" << std::endl;
            response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n{\"status\":\"success\"}";
        }
        else {
            response = "HTTP/1.1 404 Not Found\r\n\r\n404 Not Found";
        }
        
        send(clientSocket, response.c_str(), response.length(), 0);
        closesocket(clientSocket);
    }
    
    closesocket(serverSocket);
    WSACleanup();
}

void APIServer::stop() {
    isRunning = false;
}