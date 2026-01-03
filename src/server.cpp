#include "server.h"
#include <iostream>
#include <fstream>
#include <sstream>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#endif

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

void APIServer::start() {
    std::cout << "\n=== SentinelNet Dashboard Starting ===" << std::endl;
    std::cout << "Open browser: http://localhost:" << serverPort << std::endl;
    std::cout << "Press Ctrl+C to stop\n" << std::endl;
    
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
    
    isRunning = true;
    
    while (isRunning) {
        SOCKET clientSocket = accept(serverSocket, nullptr, nullptr);
        if (clientSocket == INVALID_SOCKET) continue;
        
        char buffer[4096] = {0};
        recv(clientSocket, buffer, sizeof(buffer), 0);
        
        std::string request(buffer);
        std::string response;
        
        if (request.find("GET / ") != std::string::npos || 
            request.find("GET /dashboard.html") != std::string::npos) {
            std::string html = readFile("../web/dashboard.html");
            if (html.empty()) {
                response = "HTTP/1.1 404 Not Found\r\n\r\n404 - web/dashboard.html not found";
            } else {
                response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + html;
            }
        }
        else if (request.find("GET /style.css") != std::string::npos) {
            std::string css = readFile("../web/style.css");
            response = "HTTP/1.1 200 OK\r\nContent-Type: text/css\r\n\r\n" + css;
        }
        else if (request.find("GET /script.js") != std::string::npos) {
            std::string js = readFile("../web/script.js");
            response = "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n" + js;
        }
        else if (request.find("GET /api/scans") != std::string::npos) {
            response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n{\"scans\":[]}";
        }
        else if (request.find("GET /api/alerts") != std::string::npos) {
            response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n{\"alerts\":[]}";
        }
        else if (request.find("POST /api/scan/trigger") != std::string::npos) {
            response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n{\"status\":\"triggered\"}";
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