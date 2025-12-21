#include "scanner.h"
#include <winsock2.h>
#include <iphlpapi.h>
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

    IP_ADAPTER_ADDRESSES* addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());

    if (GetAdaptersAddresses(family, flags, NULL, addresses, &size) == NO_ERROR) {
        for (IP_ADAPTER_ADDRESSES* addr = addresses; addr != NULL; addr = addr->Next) {
            IP_ADAPTER_UNICAST_ADDRESS* unicast = addr->FirstUnicastAddress;
            if (unicast) {
                char ipStr[INET_ADDRSTRLEN];
                sockaddr_in* sa = reinterpret_cast<sockaddr_in*>(unicast->Address.lpSockaddr);
                inet_ntop(AF_INET, &(sa->sin_addr), ipStr, sizeof(ipStr));

                interfaces.push_back({
                    addr->AdapterName,
                    ipStr
                });
            }
        }
    }

    return interfaces;
}

std::string NetworkScanner::scan() const {
       return "Network scan running (placeholder)";
   }

std::vector<int> NetworkScanner::scanPorts(const std::string& target, const std::vector<int>& ports) const {
    std::vector<int> open_ports;
    
    for (int port : ports) {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            continue;
        }
        
        DWORD timeout = 1000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, target.c_str(), &addr.sin_addr);
        
        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
            open_ports.push_back(port);
        }
        
        closesocket(sock);
    }
    
    return open_ports;
}