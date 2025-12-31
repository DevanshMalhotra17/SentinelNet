# SentinelNet

SentinelNet is a self-hosted network security tool. It monitors WiFi/LAN traffic, detects rogue access points, and flags suspicious activity in a home lab environment.

## Requirements (as of now)
- Windows 10/11
- CMake 3.10+
- Visual Studio 2019+ OR MinGW-w64
- C++17 compiler

## Modules
- scanner: packet capture & metadata extraction
- detection: anomaly scoring & signature engine
- simulation: local-only attack simulation framework
- server: lightweight HTTP interface for dashboard integration

## Build
SentinelNet uses CMake:

- mkdir build
- cd build
- cmake ..
- make

## Status
In development