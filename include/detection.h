#pragma once
#include <string>

class DetectionEngine {
public:
    DetectionEngine();
    std::string analyze(const std::string& metadata);
};