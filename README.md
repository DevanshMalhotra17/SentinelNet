# SentinelNet v2.0

> ## **FOR EDUCATIONAL PURPOSES ONLY**
>
> ## **SentinelNet is built strictly for learning, personal home lab use, and authorized network auditing. Do **not** use this tool on any network or machine you do not own or have explicit written permission to access. Unauthorized use of remote access, port scanning, or network monitoring tools may be **illegal** in your country. I am **not responsible** for any misuse, damage, or legal consequences caused by this software.**

---

SentinelNet is a self-hosted network security tool designed for home labs and enterprise auditing. It combines a powerful **C++17 parallel-scanning engine** with a modern web dashboard for real-time visibility — plus a built-in remote access layer so you can monitor and control the host machine from any device on your LAN.

---

## What's New in v2.0
- **High-Speed Multi-threading**: Port scans are now up to **10x faster** using hardware-accelerated concurrency.
- **Professional Interactive Shell**: A redesigned CLI shell for complex auditing without leaving your terminal.
- **Security Scoring**: Improved anomaly detection for rogue access points and suspicious device behavior.
- **Network Discovery**: Blazingly fast device discovery using CIDR and IP range expansion.
- **Remote Access Dashboard**: View screenshots, send clicks, open URLs/files, and manage the process — all from a browser on another machine.
- **Live Log Viewer**: Read and live-refresh log files directly from the dashboard.
- **Remote Management**: Restart or shut down SentinelNet remotely with uptime tracking.
- **Smart Viewer Detection**: The remote access panel is only shown to remote viewers — local users see the standard dashboard.

---

## Quick Start (Portable)

You can run SentinelNet as a portable tool without building the source.

1.  **Download**: Get the latest release from the [Live Landing Page](https://sentinelnet.vercel.app/).
2.  **Extract**: Unzip the folder (ensure the `web/` folder stays with the `.exe`).
3.  **Launch**:
    - **Dashboard**: Run `.\SentinelNet.exe -D` to start the web UI at `http://localhost:8080`.
    - **Interactive Shell**: Run `.\SentinelNet.exe` (no arguments) to enter the security shell.

---

## Remote Access Setup

SentinelNet includes a built-in remote access system so you can control the host machine from another device on your LAN. This is intended for **personal use across your own machines only**.

### On the host machine (PC being accessed):
```bat
SentinelNet.exe -D
```
The console will print two URLs:
```
Local access  : http://localhost:8080
Network access: http://192.168.1.42:8080
```

### On the remote machine (PC doing the accessing):
Open a browser and go to the **Network access** URL. You'll see the full dashboard including the Remote Access panel with:
- **Screenshot** - capture the host screen, auto-refresh every 3s
- **Remote Click** - click anywhere on the screenshot to click that spot on the host
- **Open URL** - open a URL in the host's browser (background, no focus steal)
- **Open File** - open any file on the host silently
- **Restart / Shutdown** - manage the SentinelNet process remotely
- **Log Viewer** - browse and live-refresh log files
- **Uptime / Status** - see host IP, port, version, and uptime

### Auto-start on boot (optional):
To have SentinelNet start automatically when the host boots, create a `.bat` file in the Windows startup folder (`shell:startup`):
```bat
@echo off
cd /d "C:\Path\To\SentinelNet"
start "" SentinelNet.exe -D
```

---

## Available API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/scans` | Get scan history |
| GET | `/api/alerts` | Get security alerts |
| GET | `/api/network-info` | Get detected gateway/subnet |
| GET | `/api/info` | Get host IP and port |
| GET | `/api/status` | Uptime, version, scan count |
| GET | `/api/discover` | Discover live hosts on LAN |
| GET | `/api/logs` | List log files |
| GET | `/api/logs/read?file=` | Read a specific log file |
| GET | `/api/screenshot` | Capture host screen (base64 BMP) |
| GET | `/api/online` | Heartbeat / online check |
| POST | `/api/scan/trigger` | Trigger a port scan |
| POST | `/api/audit/fingerprint` | Grab service banner |
| POST | `/api/click` | Send mouse click to host |
| POST | `/api/openurl` | Open URL on host |
| POST | `/api/openfile` | Open file on host |
| POST | `/api/restart` | Restart SentinelNet |
| POST | `/api/shutdown` | Shut down SentinelNet |
| POST | `/api/clear` | Clear scan history |

---

## Build from Source
Ensure you have **CMake 3.10+** and a **C++17** compatible compiler (MinGW or MSVC).

```bash
mkdir build
cd build
cmake ..
cmake --build .
```

---

## Project Links
- **[Live Landing Page](https://sentinelnet.vercel.app)**
- **[Interactive Dashboard Demo](https://sentinelnet.vercel.app/dashboard.html)**

---

## Security Requirements
SentinelNet requires **Npcap** for advanced packet capture features. You can download it here: [https://npcap.com/#download](https://npcap.com/#download)

---

## License
## **This project is intended for **educational and personal use only**. Do not use on networks or machines you do not own. I assume no liability for misuse.**