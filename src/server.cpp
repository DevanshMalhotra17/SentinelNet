#include "server.h"
#include "scanner.h"
#include <algorithm>
#include <ctime>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#endif

struct ScanData {
  std::string ip;
  std::vector<int> ports;
  std::string timestamp;
};

struct NetworkConfig {
  std::string gateway;
  std::string subnet;
};

std::vector<ScanData> scanResults;
std::mutex dataMutex;
NetworkConfig networkConfig;

std::string jsonResponse(const std::string &json) {
  std::string response = "HTTP/1.1 200 OK\r\n";
  response += "Content-Type: application/json\r\n";
  response += "Access-Control-Allow-Origin: *\r\n";
  response += "Content-Length: " + std::to_string(json.length()) + "\r\n";
  response += "\r\n";
  response += json;
  return response;
}

std::string detectNetworkConfig() {
  NetworkScanner scanner;
  auto interfaces = scanner.getInterfaces();

  std::string gateway = "192.168.1.1";
  std::string subnet = "192.168.1.0/24";
  std::string bestIP = "";
  int bestScore = -1;

  for (const auto &iface : interfaces) {
    if (iface.ip.find("127.0.0.1") == 0 || iface.ip.find("169.254.") == 0) continue;
    
    int score = 0;
    if (iface.ip.find("192.168.1.") == 0) score = 90;
    else if (iface.ip.find("192.168.") == 0) score = 80;
    else if (iface.ip.find("10.") == 0) score = 70;

    if (score > bestScore) {
      bestScore = score;
      bestIP = iface.ip;
    }
  }

  if (!bestIP.empty()) {
    size_t lastDot = bestIP.rfind('.');
    if (lastDot != std::string::npos) {
      std::string base = bestIP.substr(0, lastDot);
      gateway = base + ".1";
      subnet = base + ".0/24";
    }
  }

  networkConfig.gateway = gateway;
  networkConfig.subnet = subnet;
  return "{\"gateway\":\"" + gateway + "\",\"network\":\"" + subnet + "\"}";
}

APIServer::APIServer(int port) : serverPort(port), isRunning(false) {}
APIServer::~APIServer() { stop(); }

std::string readFile(const std::string &filepath) {
  std::ifstream file(filepath, std::ios::binary);
  if (!file.is_open()) return "";
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
    json += "{\"ip\":\"" + scanResults[i].ip + "\",\"timestamp\":\"" + scanResults[i].timestamp + "\",\"ports\":[";
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
  detectNetworkConfig();
  WSADATA wsa;
  WSAStartup(MAKEWORD(2, 2), &wsa);

  SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(serverPort);

  bind(serverSocket, (sockaddr *)&addr, sizeof(addr));
  listen(serverSocket, 5);

  isRunning = true;
  while (isRunning) {
    SOCKET clientSocket = accept(serverSocket, nullptr, nullptr);
    if (clientSocket == INVALID_SOCKET) continue;

    char buffer[4096];
    int bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    if (bytesRead <= 0) { closesocket(clientSocket); continue; }
    buffer[bytesRead] = '\0';
    std::string request(buffer);

    std::string response;
    if (request.find("GET /api/scans") != std::string::npos) {
      response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n" + buildScansJSON();
    } else if (request.find("GET /api/discover") != std::string::npos) {
      NetworkScanner scanner;
      std::vector<std::string> hosts = scanner.discoverActiveHosts(networkConfig.subnet);
      std::string json = "{\"hosts\":[";
      for (size_t i = 0; i < hosts.size(); i++) {
        json += "\"" + hosts[i] + "\"";
        if (i < hosts.size() - 1) json += ",";
      }
      json += "]}";
      response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n" + json;
    } else if (request.find("GET /api/network-info") != std::string::npos) {
      response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n" + 
                 std::string("{\"gateway\":\"") + networkConfig.gateway + "\",\"network\":\"" + networkConfig.subnet + "\"}";
    } else if (request.find("POST /api/scan/trigger") != std::string::npos) {
      size_t targetPos = request.find("\"target\"");
      std::string target = "127.0.0.1";
      if (targetPos != std::string::npos) {
        size_t start = request.find("\"", targetPos + 8);
        size_t end = request.find("\"", start + 1);
        if (start != std::string::npos && end != std::string::npos) target = request.substr(start + 1, end - start - 1);
      }
      NetworkScanner scanner;
      std::vector<int> commonPorts = {21, 22, 23, 25, 80, 135, 139, 443, 445, 3306, 3389, 8080};
      std::vector<int> openPorts = scanner.scanPorts(target, commonPorts);
      {
        std::lock_guard<std::mutex> lock(dataMutex);
        ScanData data = {target, openPorts, getCurrentTime()};
        scanResults.push_back(data);
      }
      response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n{\"status\":\"success\"}";
    } else if (request.find("GET / ") != std::string::npos || request.find("GET /dashboard") != std::string::npos || request.find("GET /web/dashboard") != std::string::npos) {
      std::string html = readFile("web/dashboard.html");
      response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n" + html;
    } else if (request.find("GET /style.css") != std::string::npos || request.find("GET /web/style.css") != std::string::npos) {
      response = "HTTP/1.1 200 OK\r\nContent-Type: text/css\r\n\r\n" + readFile("web/style.css");
    } else if (request.find("GET /script.js") != std::string::npos || request.find("GET /web/script.js") != std::string::npos) {
      response = "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n" + readFile("web/script.js");
    } else {
      response = "HTTP/1.1 404 Not Found\r\n\r\n404 Not Found";
    }

    send(clientSocket, response.c_str(), response.length(), 0);
    closesocket(clientSocket);
  }
  closesocket(serverSocket);
  WSACleanup();
}

void APIServer::stop() { isRunning = false; }