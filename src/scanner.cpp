#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#include "scanner.h"
#include <algorithm>
#include <array>
#include <cstdio>
#include <iphlpapi.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>


#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

NetworkScanner::NetworkScanner() {
  WSADATA wsa;
  WSAStartup(MAKEWORD(2, 2), &wsa);
}

std::string NetworkScanner::getHostname() const {
  char hostname[256];
  if (gethostname(hostname, sizeof(hostname)) == 0) {
    return std::string(hostname);
  }
  return "unknown";
}

std::vector<NetworkInterface> NetworkScanner::getInterfaces() const {
  std::vector<NetworkInterface> interfaces;

  ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
  ULONG family = AF_INET;

  ULONG size = 15000;
  std::vector<unsigned char> buffer(size);

  IP_ADAPTER_ADDRESSES *addresses =
      reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buffer.data());

  if (GetAdaptersAddresses(family, flags, NULL, addresses, &size) == NO_ERROR) {
    for (IP_ADAPTER_ADDRESSES *addr = addresses; addr != NULL;
         addr = addr->Next) {
      IP_ADAPTER_UNICAST_ADDRESS *unicast = addr->FirstUnicastAddress;
      if (unicast) {
        char ipStr[INET_ADDRSTRLEN];
        sockaddr_in *sa =
            reinterpret_cast<sockaddr_in *>(unicast->Address.lpSockaddr);
        inet_ntop(AF_INET, &(sa->sin_addr), ipStr, sizeof(ipStr));

        NetworkInterface ni;
        ni.name = addr->AdapterName;
        ni.ip = ipStr;
        interfaces.push_back(ni);
      }
    }
  }

  return interfaces;
}

std::string NetworkScanner::scan() const {
  return "Network scan running (placeholder)";
}

std::vector<int>
NetworkScanner::scanPorts(const std::string &target,
                          const std::vector<int> &ports) const {
  std::vector<int> open_ports;

  for (int port : ports) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
      continue;
    }

    DWORD timeout = 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout,
               sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout,
               sizeof(timeout));

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, target.c_str(), &addr.sin_addr);

    if (connect(sock, (sockaddr *)&addr, sizeof(addr)) == 0) {
      open_ports.push_back(port);
    }

    closesocket(sock);
  }

  return open_ports;
}

AuditResult NetworkScanner::grabBanner(const std::string &ip, int port) const {
  AuditResult result;
  result.port = port;
  result.service = "Unknown";
  result.banner = "";

  SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock == INVALID_SOCKET)
    return result;

  DWORD timeout = 2000;
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout,
             sizeof(timeout));
  setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout,
             sizeof(timeout));

  sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

  if (connect(sock, (sockaddr *)&addr, sizeof(addr)) == 0) {
    // Some services send banners immediately (SSH, FTP, SMTP)
    // For others (HTTP), we might need to send a probe

    char buffer[1024];
    int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);

    if (bytes > 0) {
      buffer[bytes] = '\0';
      result.banner = buffer;
    } else {
      // Try an HTTP probe if no immediate banner
      const char *probe = "GET / HTTP/1.0\r\n\r\n";
      send(sock, probe, strlen(probe), 0);
      bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
      if (bytes > 0) {
        buffer[bytes] = '\0';
        result.banner = buffer;
      }
    }
  }

  closesocket(sock);

  // Basic service identification from banner
  if (result.banner.find("SSH") != std::string::npos)
    result.service = "SSH";
  else if (result.banner.find("HTTP") != std::string::npos)
    result.service = "HTTP";
  else if (result.banner.find("FTP") != std::string::npos)
    result.service = "FTP";
  else if (result.banner.find("SMTP") != std::string::npos)
    result.service = "SMTP";

  return result;
}

bool NetworkScanner::isHostAlive(const std::string &target,
                                 int timeoutMs) const {
  std::string command =
      "ping -n 1 -w " + std::to_string(timeoutMs) + " " + target + " >nul 2>&1";
  int result = system(command.c_str());
  return (result == 0);
}

std::vector<std::string> NetworkScanner::getArpHosts() const {
  std::vector<std::string> hosts;
  std::array<char, 256> buffer;

  // Run arp -a command
  FILE *pipe = _popen("arp -a", "r");
  if (!pipe)
    return hosts;

  while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
    std::string line = buffer.data();

    if (line.find("Interface:") != std::string::npos ||
        line.find("Internet Address") != std::string::npos ||
        line.find("---") != std::string::npos) {
      continue;
    }

    size_t start = line.find_first_not_of(" \t");
    if (start != std::string::npos) {
      size_t end = line.find_first_of(" \t", start);
      if (end != std::string::npos) {
        std::string ip = line.substr(start, end - start);

        // Check if it's a valid IP format (has 3 dots)
        if (std::count(ip.begin(), ip.end(), '.') == 3) {
          // Filter out broadcast and multicast addresses
          
          // Skip broadcast addresses (ending in .255)
          if (ip.find(".255") != std::string::npos) {
            continue;
          }
          
          // Skip multicast addresses (224.0.0.0 to 239.255.255.255)
          if (ip.find("224.") == 0 || ip.find("225.") == 0 || 
              ip.find("226.") == 0 || ip.find("227.") == 0 ||
              ip.find("228.") == 0 || ip.find("229.") == 0 ||
              ip.find("230.") == 0 || ip.find("231.") == 0 ||
              ip.find("232.") == 0 || ip.find("233.") == 0 ||
              ip.find("234.") == 0 || ip.find("235.") == 0 ||
              ip.find("236.") == 0 || ip.find("237.") == 0 ||
              ip.find("238.") == 0 || ip.find("239.") == 0) {
            continue;
          }
          
          // Skip global broadcast
          if (ip == "255.255.255.255") {
            continue;
          }
          
          // Skip loopback
          if (ip.find("127.") == 0) {
            continue;
          }
          
          // Skip link-local (169.254.x.x)
          if (ip.find("169.254.") == 0) {
            continue;
          }
          
          hosts.push_back(ip);
        }
      }
    }
  }

  _pclose(pipe);
  return hosts;
}