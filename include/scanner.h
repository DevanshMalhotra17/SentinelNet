#pragma once

#include <mutex>
#include <string>
#include <vector>


struct NetworkInterface {
  std::string name;
  std::string ip;
};

struct AuditResult {
  int port;
  std::string service;
  std::string banner;
};

class NetworkScanner {
public:
  NetworkScanner();

  std::string getHostname() const;
  std::vector<NetworkInterface> getInterfaces() const;

  std::string scan() const;
  std::vector<int> scanPorts(const std::string &target,
                             const std::vector<int> &ports) const;

  bool isHostAlive(const std::string &target, int timeoutMs = 1000) const;

  std::vector<std::string> getArpHosts() const;
  std::vector<std::string> discoverActiveHosts(const std::string &subnet) const;
  AuditResult grabBanner(const std::string &ip, int port) const;

private:
  void scanPortRange(const std::string &target, const std::vector<int> &ports,
                     int startIdx, int endIdx, std::vector<int> &open_ports,
                     std::mutex &mutex) const;
};