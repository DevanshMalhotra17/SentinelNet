#include "server.h"
#include "scanner.h"
#include <algorithm>
#include <chrono>
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
#include <windows.h>
#include <shellapi.h>
#include <gdiplus.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "shell32.lib")
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

  std::cout << "Detecting network configuration..." << std::endl;

  // Score each interface to find the most likely "real" network
  for (const auto &iface : interfaces) {
    int score = 0;

    // Skip loopback
    if (iface.ip.find("127.0.0.1") == 0)
      continue;

    // Skip link-local addresses (169.254.x.x)
    if (iface.ip.find("169.254.") == 0)
      continue;

    // Skip common virtual network ranges
    if (iface.ip.find("192.168.56.") == 0)
      continue; // VirtualBox
    if (iface.ip.find("192.168.57.") == 0)
      continue; // VirtualBox
    if (iface.ip.find("192.168.99.") == 0)
      continue; // Docker

    // Prefer 10.0.0.x (common home/office network)
    if (iface.ip.find("10.0.0.") == 0) {
      score = 100;
    }
    // Then 192.168.1.x (most common home router)
    else if (iface.ip.find("192.168.1.") == 0) {
      score = 90;
    }
    // Then other 192.168.x.x
    else if (iface.ip.find("192.168.") == 0) {
      score = 80;
    }
    // Then other 10.x.x.x
    else if (iface.ip.find("10.") == 0) {
      score = 70;
    }

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
      std::cout << "  Detected IP: " << bestIP << std::endl;
      std::cout << "  Router: " << gateway << std::endl;
      std::cout << "  Network: " << subnet << std::endl;
    }
  } else {
    std::cout << "  No suitable network found, using defaults" << std::endl;
    std::cout << "  Router: " << gateway << std::endl;
    std::cout << "  Network: " << subnet << std::endl;
  }

  networkConfig.gateway = gateway;
  networkConfig.subnet = subnet;
  return "{\"gateway\":\"" + gateway + "\",\"network\":\"" + subnet + "\"}";
}

std::string getLocalIP() {
  WSADATA wsa;
  WSAStartup(MAKEWORD(2, 2), &wsa);

  char hostname[256];
  if (gethostname(hostname, sizeof(hostname)) != 0) {
    return "unknown";
  }

  struct addrinfo hints = {}, *res = nullptr;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  std::string bestIP = "127.0.0.1";
  int bestScore = -1;

  if (getaddrinfo(hostname, nullptr, &hints, &res) == 0) {
    for (auto p = res; p != nullptr; p = p->ai_next) {
      char ipStr[INET_ADDRSTRLEN];
      auto *sa = reinterpret_cast<sockaddr_in *>(p->ai_addr);
      inet_ntop(AF_INET, &sa->sin_addr, ipStr, sizeof(ipStr));
      std::string ip(ipStr);
      int score = 0;
      if (ip.find("127.") == 0) continue;
      if (ip.find("169.254.") == 0) continue;
      if (ip.find("10.0.0.") == 0) score = 100;
      else if (ip.find("192.168.1.") == 0) score = 90;
      else if (ip.find("192.168.") == 0) score = 80;
      else if (ip.find("10.") == 0) score = 70;
      else score = 10;

      if (score > bestScore) {
        bestScore = score;
        bestIP = ip;
      }
    }
    freeaddrinfo(res);
  }
  return bestIP;
}

APIServer::APIServer(int port) : serverPort(port), isRunning(false) {}
APIServer::~APIServer() { stop(); }

#include <filesystem>
namespace fs = std::filesystem;

std::string readFile(const std::string &filepath) {
  std::cout << "  [DEBUG] Attempting to read: " << fs::absolute(filepath)
            << std::endl;
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
      if (j < scanResults[i].ports.size() - 1)
        json += ",";
    }
    json += "]}";
    if (i < scanResults.size() - 1)
      json += ",";
  }
  json += "]}";
  return json;
}

void APIServer::start() {
  std::string networkInfo = detectNetworkConfig();

  std::string localIP = getLocalIP();
  std::cout << "\n=== SentinelNet Dashboard ===" << std::endl;
  std::cout << "  Local access  : http://localhost:" << serverPort << std::endl;
  std::cout << "  Network access: http://" << localIP << ":" << serverPort << std::endl;
  std::cout << "  Share the Network access URL with other devices on your LAN." << std::endl;
  std::cout << "  Press Ctrl+C to stop\n" << std::endl;

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

  if (bind(serverSocket, (sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
    std::cerr << "Bind failed. Port " << serverPort << " may be in use."
              << std::endl;
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
    if (clientSocket == INVALID_SOCKET)
      continue;

    std::string request;
    char buffer[4096];
    int bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    if (bytesRead > 0) {
      buffer[bytesRead] = '\0';
      request.append(buffer, bytesRead);

      if (request.find("POST") == 0) {
        size_t contentLengthPos = request.find("Content-Length: ");
        if (contentLengthPos != std::string::npos) {
          size_t start = contentLengthPos + 16;
          size_t end = request.find("\r\n", start);
          int contentLength = std::stoi(request.substr(start, end - start));

          size_t bodyStart = request.find("\r\n\r\n");
          if (bodyStart != std::string::npos) {
            bodyStart += 4;
            int currentBodyLen = request.length() - bodyStart;
            while (currentBodyLen < contentLength) {
              bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
              if (bytesRead <= 0)
                break;
              buffer[bytesRead] = '\0';
              request.append(buffer, bytesRead);
              currentBodyLen += bytesRead;
            }
          }
        }
      }
    }

    if (request.empty()) {
      closesocket(clientSocket);
      continue;
    }

    std::string response;
    std::cout << "[REQUEST] " << request.substr(0, request.find("\r\n")) << " ("
              << request.length() << " bytes)" << std::endl;

    if (request.find("GET /hack.js") != std::string::npos) {
      std::string js = readFile("hack.js");
      if (js.empty())
        js = readFile("web/hack.js");
      if (js.empty())
        js = readFile("../web/hack.js");
      if (js.empty()) {
        response = "HTTP/1.1 404 Not Found\r\n\r\n404 - hack.js not found";
      } else {
        response =
            "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n" +
            js;
      }
    } else if (request.find("GET /hack") != std::string::npos) {
      std::string html = readFile("hack.html");
      if (html.empty())
        html = readFile("web/hack.html");
      if (html.empty())
        html = readFile("../web/hack.html");
      if (html.empty()) {
        response = "HTTP/1.1 404 Not Found\r\n\r\n404 - Hack page not found";
      } else {
        response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + html;
      }
    } else if (request.find("GET / ") != std::string::npos ||
               request.find("GET /dashboard.html") != std::string::npos) {
      std::string html = readFile("dashboard.html");
      if (html.empty()) html = readFile("web/dashboard.html");
      if (html.empty()) html = readFile("sentinelnet/web/dashboard.html");
      if (html.empty()) html = readFile("../web/dashboard.html");
      if (html.empty()) html = readFile("index.html");
      if (html.empty()) html = readFile("web/index.html");

      if (html.empty()) {
        std::cerr << "  [ERROR] Dashboard HTML not found in any path!" << std::endl;
        response = "HTTP/1.1 404 Not Found\r\n\r\n404 - HTML file not found";
      } else {
        std::string injection = "<script>window.IS_REMOTE_VIEWER=true;</script>";
        size_t headClose = html.find("</head>");
        if (headClose != std::string::npos) html.insert(headClose, injection);
        response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + html;
      }
    } else if (request.find("GET /style.css") != std::string::npos) {
      std::string css = readFile("style.css");
      if (css.empty())
        css = readFile("web/style.css");
      if (css.empty())
        css = readFile("../web/style.css");
      if (css.empty())
        css = readFile("sentinelnet/web/style.css");
      response = "HTTP/1.1 200 OK\r\nContent-Type: text/css\r\n\r\n" + css;
    } else if (request.find("GET /script.js") != std::string::npos) {
      std::string js = readFile("script.js");
      if (js.empty())
        js = readFile("web/script.js");
      if (js.empty())
        js = readFile("../web/script.js");
      if (js.empty())
        js = readFile("sentinelnet/web/script.js");
      response =
          "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n" +
          js;
    } else if (request.find("GET /hack1.js") != std::string::npos) {
      std::string js = readFile("hack1.js");
      if (js.empty())
        js = readFile("../web/hack1.js");
      if (js.empty()) {
        response = "HTTP/1.1 404 Not Found\r\n\r\n404 - hack1.js not found";
      } else {
        response =
            "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n" +
            js;
      }
    } else if (request.find("GET /api/scans") != std::string::npos) {
      std::string json = buildScansJSON();
      response = "HTTP/1.1 200 OK\r\nContent-Type: "
                 "application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n" +
                 json;
    } else if (request.find("GET /api/alerts") != std::string::npos) {
      response = "HTTP/1.1 200 OK\r\nContent-Type: "
                 "application/json\r\nAccess-Control-Allow-Origin: "
                 "*\r\n\r\n{\"alerts\":[]}";
    } else if (request.find("GET /api/discover") != std::string::npos) {
      std::cout
          << "[API] Network discovery requested (using fast parallel scan)"
          << std::endl;

      NetworkScanner scanner;
      std::vector<std::string> hosts =
          scanner.discoverActiveHosts(networkConfig.subnet);

      std::string json = "{\"hosts\":[";
      for (size_t i = 0; i < hosts.size(); i++) {
        json += "\"" + hosts[i] + "\"";
        if (i < hosts.size() - 1)
          json += ",";
      }
      json += "]}";
      std::cout << "[API] Discovery complete. Found " << hosts.size()
                << " hosts" << std::endl;
      response = "HTTP/1.1 200 OK\r\nContent-Type: "
                 "application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n" +
                 json;
    } else if (request.find("GET /api/network-info") != std::string::npos) {
      std::string json = "{\"gateway\":\"" + networkConfig.gateway +
                         "\",\"network\":\"" + networkConfig.subnet + "\"}";
      response = "HTTP/1.1 200 OK\r\nContent-Type: "
                 "application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n" +
                 json;
    } else if (request.find("GET /api/info") != std::string::npos) {
      std::string localIP = getLocalIP();
      std::string json = "{\"host\":\"" + localIP + "\",\"port\":" +
                         std::to_string(serverPort) + "}";
      response = "HTTP/1.1 200 OK\r\nContent-Type: "
                 "application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n" +
                 json;
    } else if (request.find("POST /api/scan/trigger") != std::string::npos) {
      std::cout << "[API] Scan trigger received" << std::endl;

      size_t bodyStart = request.find("\r\n\r\n");
      std::string target = "127.0.0.1";

      if (bodyStart != std::string::npos) {
        std::string body = request.substr(bodyStart + 4);
        std::cout << "[DEBUG] Body: " << body << std::endl;
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

      std::vector<int> openPorts;
      try {
        NetworkScanner scanner;

        std::cout << "[PING] Checking if " << target << " is reachable..."
                  << std::endl;
        bool isAlive = scanner.isHostAlive(target, 1000);

        if (!isAlive) {
          std::cout << "[PING] Host " << target << " is not responding to ping"
                    << std::endl;
        }

        std::vector<int> commonPorts = {21,  22,  23,  25,   80,   135, 139, 443, 445, 3306, 3389, 8080};
        openPorts = scanner.scanPorts(target, commonPorts);

        std::cout << "[SCAN] Scan completed successfully" << std::endl;
      } catch (const std::exception &e) {
        std::cerr << "[ERROR] Scan exception: " << e.what() << std::endl;
      } catch (...) {
        std::cerr << "[ERROR] Unknown scan error occurred" << std::endl;
      }

      {
        std::lock_guard<std::mutex> lock(dataMutex);
        ScanData data;
        data.ip = target;
        data.ports = openPorts;
        data.timestamp = getCurrentTime();
        scanResults.push_back(data);
        std::cout << "[DATA] Added scan result: " << target << " (" << openPorts.size() << " ports)" << std::endl;
      }

      std::cout << "[SCAN] Completed scan of " << target << " - "
                << openPorts.size() << " ports open" << std::endl;

      response = "HTTP/1.1 200 OK\r\nContent-Type: "
                 "application/json\r\nAccess-Control-Allow-Origin: "
                 "*\r\n\r\n{\"status\":\"success\"}";
    } else if (request.find("POST /api/audit/fingerprint") !=
               std::string::npos) {
      std::cout << "[API] Fingerprint request received" << std::endl;

      // Parse body
      size_t bodyStart = request.find("\r\n\r\n");
      if (bodyStart == std::string::npos) {
        response = jsonResponse("{\"error\":\"No body\"}");
      } else {
        std::string body = request.substr(bodyStart + 4);
        std::string target = "";
        int port = 0;
        size_t targetPos = body.find("\"target\"");
        if (targetPos != std::string::npos) {
          size_t start = body.find("\"", targetPos + 8);
          size_t end = body.find("\"", start + 1);
          if (start != std::string::npos && end != std::string::npos) {
            target = body.substr(start + 1, end - start - 1);
          }
        }
        size_t portPos = body.find("\"port\"");
        if (portPos != std::string::npos) {
          size_t colonPos = body.find(":", portPos);
          if (colonPos != std::string::npos) {
            size_t numStart = colonPos + 1;
            while (numStart < body.length() &&
                   (body[numStart] == ' ' || body[numStart] == '\t')) {
              numStart++;
            }
            std::string portStr = "";
            while (numStart < body.length() && isdigit(body[numStart])) {
              portStr += body[numStart++];
            }
            if (!portStr.empty()) {
              port = std::stoi(portStr);
            }
          }
        }
        if (target.empty() || port == 0) {
          response = jsonResponse("{\"error\":\"Invalid request\"}");
        } else {
          std::cout << "[FINGERPRINT] Grabbing banner from " << target << ":" << port << std::endl;

          try {
            NetworkScanner scanner;
            AuditResult result = scanner.grabBanner(target, port);

            std::string json = "{";
            json += "\"port\":" + std::to_string(result.port) + ",";
            json += "\"service\":\"" + result.service + "\",";

            std::string escapedBanner = result.banner;
            size_t pos = 0;
            while ((pos = escapedBanner.find("\"", pos)) != std::string::npos) {
              escapedBanner.replace(pos, 1, "\\\"");
              pos += 2;
            }
            pos = 0;
            while ((pos = escapedBanner.find("\n", pos)) != std::string::npos) {
              escapedBanner.replace(pos, 1, "\\n");
              pos += 2;
            }
            pos = 0;
            while ((pos = escapedBanner.find("\r", pos)) != std::string::npos) {
              escapedBanner.replace(pos, 1, "\\r");
              pos += 2;
            }

            json += "\"banner\":\"" + escapedBanner + "\"";
            json += "}";

            std::cout << "[FINGERPRINT] Service: " << result.service
                      << std::endl;
            response =
                "HTTP/1.1 200 OK\r\nContent-Type: "
                "application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n" +
                json;
          } catch (...) {
            response = jsonResponse("{\"error\":\"Fingerprint failed\"}");
          }
        }
      }

    } else if (request.find("POST /api/clear") != std::string::npos) {
      std::lock_guard<std::mutex> lock(dataMutex);
      scanResults.clear();
      std::cout << "[DATA] Cleared all scan results" << std::endl;
      response = "HTTP/1.1 200 OK\r\nContent-Type: "
                 "application/json\r\nAccess-Control-Allow-Origin: "
                 "*\r\n\r\n{\"status\":\"success\"}";

    // REMOTE MANAGEMENT ENDPOINTS

    } else if (request.find("GET /api/status") != std::string::npos) {
      static auto startTime = std::chrono::steady_clock::now();
      auto now = std::chrono::steady_clock::now();
      int uptimeSec = (int)std::chrono::duration_cast<std::chrono::seconds>(now - startTime).count();
      std::string localIP = getLocalIP();
      std::string json = "{";
      json += "\"version\":\"2.0\",";
      json += "\"host\":\"" + localIP + "\",";
      json += "\"port\":" + std::to_string(serverPort) + ",";
      json += "\"uptime\":" + std::to_string(uptimeSec) + ",";
      json += "\"scans\":" + std::to_string(scanResults.size());
      json += "}";
      response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n" + json;

    } else if (request.find("GET /api/logs") != std::string::npos &&
               request.find("/api/logs/read") == std::string::npos) {
      std::string json = "{\"files\":[";
      bool first = true;
      try {
        if (fs::exists("logs") && fs::is_directory("logs")) {
          for (const auto &entry : fs::directory_iterator("logs")) {
            if (entry.path().extension() == ".log") {
              if (!first) json += ",";
              json += "\"" + entry.path().filename().string() + "\"";
              first = false;
            }
          }
        }
      } catch (...) {}
      json += "]}";
      response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n" + json;

    } else if (request.find("GET /api/logs/read") != std::string::npos) {
      std::string filename = "";
      size_t fileParam = request.find("file=");
      if (fileParam != std::string::npos) {
        size_t start = fileParam + 5;
        size_t end = request.find(" ", start);
        if (end == std::string::npos) end = request.find("\r", start);
        filename = request.substr(start, end - start);
      }
      if (filename.find("..") != std::string::npos || filename.find("/") != std::string::npos) {
        response = jsonResponse("{\"error\":\"Invalid filename\"}");
      } else {
        std::string content = readFile("logs/" + filename);
        if (content.empty()) {
          response = jsonResponse("{\"error\":\"File not found or empty\"}");
        } else {
          std::string escaped = "";
          for (char c : content) {
            if (c == '"')       escaped += "\\\"";
            else if (c == '\\') escaped += "\\\\";
            else if (c == '\n') escaped += "\\n";
            else if (c == '\r') escaped += "\\r";
            else                escaped += c;
          }
          std::string json = "{\"file\":\"" + filename + "\",\"content\":\"" + escaped + "\"}";
          response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n" + json;
        }
      }

    } else if (request.find("POST /api/shutdown") != std::string::npos) {
      std::cout << "[REMOTE] Shutdown requested via dashboard" << std::endl;
      response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n{\"status\":\"shutting_down\"}";
      send(clientSocket, response.c_str(), response.length(), 0);
      closesocket(clientSocket);
      closesocket(serverSocket);
      WSACleanup();
      exit(0);

    } else if (request.find("POST /api/restart") != std::string::npos) {
      std::cout << "[REMOTE] Restart requested via dashboard" << std::endl;
      response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n{\"status\":\"restarting\"}";
      send(clientSocket, response.c_str(), response.length(), 0);
      closesocket(clientSocket);
      char exePath[MAX_PATH];
      GetModuleFileNameA(NULL, exePath, MAX_PATH);
      std::string cmd = std::string("\"") + exePath + "\" -D";
      STARTUPINFOA si = { sizeof(si) };
      PROCESS_INFORMATION pi;
      CreateProcessA(NULL, const_cast<char*>(cmd.c_str()), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
      CloseHandle(pi.hProcess);
      CloseHandle(pi.hThread);
      closesocket(serverSocket);
      WSACleanup();
      exit(0);

    } else if (request.find("GET /api/screenshot") != std::string::npos) {
      HDC hdcScreen = GetDC(NULL);
      HDC hdcMem = CreateCompatibleDC(hdcScreen);
      int w = GetSystemMetrics(SM_CXSCREEN);
      int h = GetSystemMetrics(SM_CYSCREEN);
      HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, w, h);
      SelectObject(hdcMem, hBitmap);
      BitBlt(hdcMem, 0, 0, w, h, hdcScreen, 0, 0, SRCCOPY);

      std::string tmpPath = std::string(getenv("TEMP")) + "\\sentinelnet_shot.bmp";
      BITMAPFILEHEADER bfh = {};
      BITMAPINFOHEADER bih = {};
      bih.biSize = sizeof(BITMAPINFOHEADER);
      bih.biWidth = w;
      bih.biHeight = -h;
      bih.biPlanes = 1;
      bih.biBitCount = 24;
      bih.biCompression = BI_RGB;
      int rowSize = ((w * 3 + 3) & ~3);
      bih.biSizeImage = rowSize * h;
      bfh.bfType = 0x4D42;
      bfh.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
      bfh.bfSize = bfh.bfOffBits + bih.biSizeImage;
      std::vector<uint8_t> pixels(bih.biSizeImage);
      GetDIBits(hdcMem, hBitmap, 0, h, pixels.data(), (BITMAPINFO*)&bih, DIB_RGB_COLORS);
      std::vector<uint8_t> bmpData;
      bmpData.insert(bmpData.end(), (uint8_t*)&bfh, (uint8_t*)&bfh + sizeof(bfh));
      bmpData.insert(bmpData.end(), (uint8_t*)&bih, (uint8_t*)&bih + sizeof(bih));
      bmpData.insert(bmpData.end(), pixels.begin(), pixels.end());
      static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
      std::string b64str;
      b64str.reserve(((bmpData.size() + 2) / 3) * 4);
      for (size_t i = 0; i < bmpData.size(); i += 3) {
        uint32_t val = bmpData[i] << 16;
        if (i+1 < bmpData.size()) val |= bmpData[i+1] << 8;
        if (i+2 < bmpData.size()) val |= bmpData[i+2];
        b64str += b64[(val >> 18) & 63];
        b64str += b64[(val >> 12) & 63];
        b64str += (i+1 < bmpData.size()) ? b64[(val >> 6) & 63] : '=';
        b64str += (i+2 < bmpData.size()) ? b64[val & 63] : '=';
      }

      DeleteObject(hBitmap);
      DeleteDC(hdcMem);
      ReleaseDC(NULL, hdcScreen);

      std::string json = "{\"width\":" + std::to_string(w) + ",\"height\":" + std::to_string(h) + ",\"data\":\"" + b64str + "\"}";
      response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n" + json;

    } else if (request.find("POST /api/click") != std::string::npos) {
      size_t bodyStart = request.find("\r\n\r\n");
      int x = 0, y = 0;
      if (bodyStart != std::string::npos) {
        std::string body = request.substr(bodyStart + 4);
        auto parseNum = [&](const std::string& key) -> int {
          size_t pos = body.find("\"" + key + "\"");
          if (pos == std::string::npos) return 0;
          size_t col = body.find(":", pos);
          if (col == std::string::npos) return 0;
          return std::stoi(body.substr(col + 1));
        };
        x = parseNum("x");
        y = parseNum("y");
      }
      int screenW = GetSystemMetrics(SM_CXSCREEN);
      int screenH = GetSystemMetrics(SM_CYSCREEN);
      INPUT inp[3] = {};
      inp[0].type = INPUT_MOUSE;
      inp[0].mi.dx = (x * 65535) / screenW;
      inp[0].mi.dy = (y * 65535) / screenH;
      inp[0].mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE;
      inp[1].type = INPUT_MOUSE;
      inp[1].mi.dwFlags = MOUSEEVENTF_LEFTDOWN;
      inp[2].type = INPUT_MOUSE;
      inp[2].mi.dwFlags = MOUSEEVENTF_LEFTUP;
      SendInput(3, inp, sizeof(INPUT));
      response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n{\"status\":\"clicked\",\"x\":" + std::to_string(x) + ",\"y\":" + std::to_string(y) + "}";

    } else if (request.find("POST /api/openurl") != std::string::npos) {
      size_t bodyStart = request.find("\r\n\r\n");
      std::string url = "";
      if (bodyStart != std::string::npos) {
        std::string body = request.substr(bodyStart + 4);
        size_t pos = body.find("\"url\"");
        if (pos != std::string::npos) {
          size_t s = body.find("\"", pos + 5); 
          size_t e = body.find("\"", s + 1);
          if (s != std::string::npos && e != std::string::npos)
            url = body.substr(s + 1, e - s - 1);
        }
      }
      if (!url.empty()) {
        ShellExecuteA(NULL, "open", url.c_str(), NULL, NULL, SW_SHOWMINNOACTIVE);
        response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n{\"status\":\"opened\"}";
      } else {
        response = jsonResponse("{\"error\":\"No URL provided\"}");
      }

    } else if (request.find("POST /api/openfile") != std::string::npos) {
      size_t bodyStart = request.find("\r\n\r\n");
      std::string filepath = "";
      if (bodyStart != std::string::npos) {
        std::string body = request.substr(bodyStart + 4);
        size_t pos = body.find("\"path\"");
        if (pos != std::string::npos) {
          size_t s = body.find("\"", pos + 6);
          size_t e = body.find("\"", s + 1);
          if (s != std::string::npos && e != std::string::npos)
            filepath = body.substr(s + 1, e - s - 1);
        }
      }
      if (!filepath.empty()) {
        ShellExecuteA(NULL, "open", filepath.c_str(), NULL, NULL, SW_SHOWMINNOACTIVE);
        response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n{\"status\":\"opened\"}";
      } else {
        response = jsonResponse("{\"error\":\"No path provided\"}");
      }

    } else if (request.find("GET /api/online") != std::string::npos) {
      std::string localIP = getLocalIP();
      std::string json = "{\"online\":true,\"host\":\"" + localIP + "\",\"port\":" + std::to_string(serverPort) + "}";
      response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n" + json;

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