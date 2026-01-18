#pragma once

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

  AuditResult grabBanner(const std::string &ip, int port) const;

  bool isHostAlive(const std::string &target, int timeoutMs = 500) const;

  std::vector<std::string> getArpHosts() const;
};