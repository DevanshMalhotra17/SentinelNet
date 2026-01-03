#pragma once
#include <string>

class APIServer {
public:
    APIServer(int port = 8080);
    ~APIServer();
    
    void start();
    void stop();

private:
    int serverPort;
    bool isRunning;
};