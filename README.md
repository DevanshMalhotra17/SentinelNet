# SentinelNet

A standalone network security tool for your home lab.

## Easy Start (Recommended)

You can run SentinelNet as a portable tool without building the source.

1.  **Download**: [SentinelNet_v1.0.zip]
2.  **Extract**: Unzip the folder to your computer.
3.  **Run**: Double-click `run.bat` (this starts the dashboard on port 8080).
4.  **Access**: Open your browser to [http://localhost:8080](http://localhost:8080).

---

## Technical Overview
SentinelNet is a C++ backend coupled with a modern web frontend. It monitors network traffic, detects active hosts, and performs security audits.

## Requirements
- Windows 10/11
- CMake 3.10+
- Visual Studio 2019+ OR MinGW-w64
- C++17 compiler

## Modules
- scanner: packet capture & metadata extraction
- detection: anomaly scoring & signature engine
- server: lightweight HTTP interface for dashboard integration

## Build
SentinelNet uses CMake:

- mkdir build
- cd build
- cmake ..
- make