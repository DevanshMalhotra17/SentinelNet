# SentinelNet

SentinelNet is a self-hosted network security tool designed for home labs and enterprise auditing. It combines a powerful **C++17 parallel-scanning engine** with a modern web dashboard for real-time visibility.

---

## What's New
- **High-Speed Multi-threading**: Port scans are now up to **10x faster** using hardware-accelerated concurrency.
- **Professional Interactive Shell**: A redesigned CLI shell for complex auditing without leaving your terminal.
- **Security Scoring**: Improved anomaly detection for rogue access points and suspicious device behavior.
- **Network Discovery**: Blazingly fast device discovery using CIDR and IP range expansion.

---

## Quick Start (Portable)

You can run SentinelNet as a portable tool without building the source.

<1.  **Download**: Get the latest release from the [Live Landing Page](https://sentinelnet.vercel.app/).
2.  **Extract**: Unzip the folder (ensure the `web/` folder stays with the `.exe`).
3.  **Launch**:
    - **Dashboard**: Run `.\SentinelNet.exe -D` to start the web UI at `http://localhost:8080`.
    - **Interactive Shell**: Run `.\SentinelNet.exe` (no arguments) to enter the security shell.

> **Prerequisite**: SentinelNet requires **Npcap** for packet capture. Download it at [npcap.com](https://npcap.com/#download) and install it before running.

---

## Remote Access

SentinelNet includes a full remote access system for controlling the host machine from any device, anywhere in the world.

### How it works:
1. PC2 runs `SentinelNet.exe` as administrator (once, first time only)
2. SentinelNet installs itself as a silent Windows service
3. On every boot, it starts a Cloudflare tunnel and reports the public URL to your connect page
4. Open `sentinelnet.vercel.app/connect.html` on PC1 — click **Connect to PC2**

### Dashboard features:
- **Screenshot** — capture the host screen on demand
- **Live Remote Desktop** — stream PC2's screen at 15fps, click anywhere to control it
- **Remote Click / Right-click** — full mouse control
- **Type / Keypress** — send text and special keys remotely
- **Open URL** — open a URL in the host's browser silently
- **Open File** — open any file on the host silently
- **Restart / Shutdown** — manage the SentinelNet process remotely
- **Log Viewer** — browse and live-refresh log files
- ⏱**Uptime / Status** — see host IP, port, version, and uptime

### Access URLs:
| URL | What it does |
|-----|-------------|
| `sentinelnet.vercel.app/connect.html` | PC1 connect page — shows PC2 status and link |
| `[tunnel-url]/` | Full dashboard |
| `[tunnel-url]/remote` | Live remote desktop viewer |

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
| GET | `/api/stream` | Live screen stream (MJPEG) |
| GET | `/api/online` | Heartbeat / online check |
| POST | `/api/scan/trigger` | Trigger a port scan |
| POST | `/api/audit/fingerprint` | Grab service banner |
| POST | `/api/click` | Send left click to host |
| POST | `/api/rightclick` | Send right click to host |
| POST | `/api/key` | Send keypress to host |
| POST | `/api/type` | Send text input to host |
| POST | `/api/openurl` | Open URL on host |
| POST | `/api/openfile` | Open file on host |
| POST | `/api/restart` | Restart SentinelNet |
| POST | `/api/shutdown` | Shut down SentinelNet |
| POST | `/api/clear` | Clear scan history |

---

## Project Links
- **[Live Landing Page](https://sentinelnet.vercel.app)**
- **[Interactive Dashboard Demo](https://sentinelnet.vercel.app/web/dashboard.html)**
> **Note:** The demo shows the UI only. Full scanning functionality requires running the compiled executable (`SentinelNet.exe`) locally with admin privileges.

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

## Security Requirements
SentinelNet requires **Npcap** for advanced packet capture features. You can download it here: [https://npcap.com/#download](https://npcap.com/#download)