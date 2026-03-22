# SentinelNet

SentinelNet is a high-performance network security scanner and auditing tool. It is designed to be a standalone, self-hosted solution for home labs and enterprise auditing. 

SentinelNet features a powerful **C++17 parallel-scanning engine** and a modern **web-based project dashboard** for real-time visibility into your network security.

## Project Links
- **[Live Landing Page](https://sentinelnet.vercel.app)**
- **[Interactive Dashboard Demo](https://sentinelnet.vercel.app/web/dashboard.html)**
- **[SentinelNet v2.0 (Remote Access)](https://github.com/DevanshMalhotra17/SentinelNet_v2.0)**

> [!NOTE]
> ### Demo vs Full Functionality
> The **Interactive Dashboard Demo** is a static, visual preview of SentinelNet’s user interface.  
> It is intended for demonstration purposes only.
>
> - Buttons and controls in the demo are **non-functional by design**
> - No real network scanning or API interaction occurs in the demo
> - The demo exists solely to showcase the UI/UX
>
> To access full functionality (including scanning, API usage, and the interactive shell), you must run the **SentinelNet executable locally**.
>
> Please refer to the **Quick Start** section below for instructions on running the full application.

---

> [!CAUTION]
> **USE AT YOUR OWN RISK.** This tool is for educational and ethical auditing purposes only. Whoever has access to the SentinelNet interface potentially has access to information on your host machine. I am **NOT responsible** for any damages or misuse caused by this software.

---

## Key Features

- **Fast Port Scanning**: Port scans are up to **10x faster** using hardware-accelerated concurrency.
- **Intrusion Detection**: Automatic identification of rogue services and common security vulnerabilities on your network.
- **Interactive Security Shell**: A complete command-line interface for complex auditing without leaving your terminal.
- **Network Discovery**: Quickly discover active hosts on your local network using CIDR or IP range expansion.
- **Web Dashboard**: A modern, real-time UI that provides a visualized overview of your network scanning activity.

---

## Quick Start

SentinelNet is a single portable executable. No installation is required, but **Npcap** must be installed on the host machine.

### Prerequisites
- **Download Npcap**: SentinelNet requires Npcap for raw packet monitoring. Download and install it from [npcap.com](https://npcap.com/#download).

### Running SentinelNet
1.  **Extract the ZIP**: Ensure the `web/` folder remains in the same directory as `SentinelNet.exe`.
2.  **Launch Dashboard**: 
    - Run `.\SentinelNet.exe -D` in your terminal.
    - Open your browser to `http://localhost:8080`.
3.  **Use the Shell**:
    - Run `.\SentinelNet.exe` (no arguments) to enter the interactive security shell.
    - Type `-h` or `--help` inside the shell for a list of commands.

---

## Building from Source

Ensure you have **CMake 3.10+** and a **C++17** compatible compiler (MinGW or MSVC).

```bash
# Create a build directory
mkdir build && cd build

# Configure and build
cmake ..
cmake --build .
```

The compiled executable and distribution files will be located in the `dist/` folder.

---

## API Endpoints

SentinelNet provides a local REST API that powers the dashboard:

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/scans` | Retrieve the history of recent port scans |
| GET | `/api/network-info` | Get detected network gateway and subnet |
| GET | `/api/discover` | Scan the LAN for active hosts |
| POST | `/api/scan/trigger` | Manually trigger a port scan for a target IP |

---

## License
This project is intended for educational and ethical security auditing purposes only. Use it responsibly on networks you own or have explicit permission to audit.