#ifndef NETWORKSCANNER_H
#define NETWORKSCANNER_H

#include <string>
#include <vector>

struct NetworkInterface {
    std::string name;
    std::string ip;
};

class NetworkScanner {
public:
    NetworkScanner();

    std::string getHostname() const;
    std::vector<NetworkInterface> getInterfaces() const;
    
    std::string scan() const;
};

#endif