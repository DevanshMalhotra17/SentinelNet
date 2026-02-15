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
#include <functional>
#include <iostream>
#include <mutex>
#include <thread>
#include <vector>

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
  if (ports.empty())
    return {};

  int numThreads =
      std::min((int)std::thread::hardware_concurrency(), (int)ports.size());
  if (numThreads < 1)
    numThreads = 1;

  std::vector<int> open_ports;
  std::mutex openPortsMutex;
  std::vector<std::thread> threads;

  int portsPerThread = (int)ports.size() / numThreads;
  int remainingPorts = (int)ports.size() % numThreads;

  int currentStart = 0;
  for (int i = 0; i < numThreads; i++) {
    int count = portsPerThread + (i < remainingPorts ? 1 : 0);
    int currentEnd = currentStart + count;

    threads.emplace_back(&NetworkScanner::scanPortRange, this, target,
                         std::ref(ports), currentStart, currentEnd,
                         std::ref(open_ports), std::ref(openPortsMutex));

    currentStart = currentEnd;
  }

  for (auto &t : threads) {
    if (t.joinable())
      t.join();
  }

  // Sort results for cleaner output
  std::sort(open_ports.begin(), open_ports.end());
  return open_ports;
}

void NetworkScanner::scanPortRange(const std::string &target,
                                   const std::vector<int> &ports, int startIdx,
                                   int endIdx, std::vector<int> &open_ports,
                                   std::mutex &mutex) const {
  for (int i = startIdx; i < endIdx; i++) {
    int port = ports[i];
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
      continue;
    }

    // Short timeout for efficiency
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
      std::lock_guard<std::mutex> lock(mutex);
      open_ports.push_back(port);
    }

    closesocket(sock);
  }
}

AuditResult NetworkScanner::grabBanner(const std::string &ip, int port) const {
  AuditResult result;
  result.port = port;
  result.service = "unknown";
  result.banner = "";

  SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock == INVALID_SOCKET) {
    return result;
  }

  DWORD timeout = 2000;
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout,
             sizeof(timeout));

  sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

  if (connect(sock, (sockaddr *)&addr, sizeof(addr)) == 0) {
    char buffer[1024];
    int bytesReceived = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (bytesReceived > 0) {
      buffer[bytesReceived] = '\0';
      result.banner = buffer;
    }
  }

  closesocket(sock);
  return result;
}

bool NetworkScanner::isHostAlive(const std::string &target,
                                 int timeoutMs) const {
  std::vector<int> commonPorts = {135, 445, 80, 443, 22, 3389};
  
  for (int port : commonPorts) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) continue;

    DWORD timeout = timeoutMs;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, target.c_str(), &addr.sin_addr);

    bool alive = (connect(sock, (sockaddr *)&addr, sizeof(addr)) == 0);
    closesocket(sock);
    
    if (alive) return true;
  }
  
  return false;
}

std::vector<std::string> NetworkScanner::getArpHosts() const {
  std::vector<std::string> hosts;
  return hosts;
}

std::vector<std::string> NetworkScanner::discoverActiveHosts(const std::string& subnet) const {
    std::vector<std::string> hosts;
    return hosts;
}
