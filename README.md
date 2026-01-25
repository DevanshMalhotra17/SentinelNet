# SentinelNet

**SentinelNet** is a network security monitoring and discovery tool designed for Windows environments. It combines a powerful C++ backend with a web-based dashboard to provide real-time visibility into your network's security posture.

## Features

### Network Discovery
- **Multi-threaded Ping Sweeps**: Discover active hosts across entire subnets in seconds.
- **ARP Table Integration**: Leverage local ARP cache for rapid device identification.
- **Intelligent Subnet Detection**: Automatically identifies your gateway and network mask.

### Security Analysis Engine
- **Vulnerability Scoring**: Categorizes open ports into threat levels (Critical, High, Medium, Low).
- **Service Fingerprinting**: Performs banner grabbing to identify running services (SSH, HTTP, FTP, SMTP, etc.).
- **Smart Recommendations**: Provides actionable security advice for discovered risks.

### Real-time Web Dashboard
- **Scan Management**: Trigger quick scans (Localhost, Router, Full Network) or custom targets directly from the browser.
- **Live Notifications**: Visual alerts and notifications for scan progress and security findings.

### Command Line Power
- **Flexible CLI**: Full feature parity via command line arguments.
- **Logging System**: Persistent logging of all security events and scan results.

---

## Tech Stack

SentinelNet is built with a modular architecture focused on performance and reliability.

- **C++17 Backend**: High-performance core utilizing WinSock2 and the Win32 API.
- **Frontend**: A modern Web Application built with Vanilla JavaScript, HTML5, and CSS3.

---

## Getting Started

### Prerequisites
- **Windows 10/11**
- **Visual Studio 2019+** (or MinGW-w64)
- **CMake 3.10+**
- **Npcap SDK** (Install to `C:/npcap-sdk`)

### Build Instructions
```powershell
# Clone the repository
git clone https://github.com/DevanshMalhotra17/SentinelNet.git
cd SentinelNet

# Create build directory
mkdir build
cd build

# Configure and build
cmake ..
cmake --build . --config Release
```

### Running SentinelNet
To start the web dashboard:
```powershell
./SentinelNet.exe --dashboard
```
Access the dashboard at `http://localhost:8080`.
