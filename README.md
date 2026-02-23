# SentinelNet v2.0

> ⚠️ **FOR EDUCATIONAL PURPOSES ONLY**
>
> ## SentinelNet is built strictly for learning, personal home lab use, and authorized network auditing. Do **not** use this tool on any network or machine you do not own or have explicit written permission to access. Unauthorized use of remote access, port scanning, or network monitoring tools may be **illegal** in your country. I am **not responsible** for any misuse, damage, or legal consequences caused by this software.

---

SentinelNet is a self-hosted network security tool designed for home labs and enterprise auditing. It combines a powerful **C++17 parallel-scanning engine** with a modern web dashboard for real-time visibility and a full remote access and control layer so you can monitor, control, and see the host machine from anywhere in the world.

---

## What's New in v2.0
- **High-Speed Multi-threading**: Port scans are now up to **10x faster** using hardware-accelerated concurrency.
- **Professional Interactive Shell**: A redesigned CLI shell for complex auditing without leaving your terminal.
- **Security Scoring**: Improved anomaly detection for rogue access points and suspicious device behavior.
- **Network Discovery**: Blazingly fast device discovery using CIDR and IP range expansion.
- **Silent Windows Service**: Installs itself as a hidden background service on first run — auto-starts on every boot, no terminal, no tray icon.
- **Cloudflare Tunnel**: Built-in Cloudflare tunnel gives you a public URL to access the dashboard from anywhere in the world — no port forwarding, no static IP needed.
- **Live Remote Desktop**: Stream PC2's screen live at 15fps with full click, right-click, keyboard, and typing support directly in your browser.
- **Remote Access Dashboard**: View screenshots, send clicks, open URLs/files, and manage the process — all from a browser on another device.
- **Live Log Viewer**: Read and live-refresh log files directly from the dashboard.
- **Remote Management**: Restart or shut down SentinelNet remotely with uptime tracking.

---

## Quick Start

1. **Download**: Get the latest release from the [Live Landing Page](https://sentinelnet.vercel.app/).
2. **Extract**: Unzip the folder (ensure the `web/` folder stays with the `.exe`).
3. **Run as Administrator**: Right-click `SentinelNet.exe` → **Run as administrator**. The window will close on its own — that's normal. It's now running silently in the background and will auto-start on every boot.
4. **Connect from another device**: Open `sentinelnet.vercel.app/connect.html` on PC1 — wait ~30 seconds for the tunnel to start, then click the connect button.

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
- 📸 **Screenshot** — capture the host screen on demand
- 🖥️ **Live Remote Desktop** — stream PC2's screen at 15fps, click anywhere to control it
- 🖱️ **Remote Click / Right-click** — full mouse control
- ⌨️ **Type / Keypress** — send text and special keys remotely
- 🌐 **Open URL** — open a URL in the host's browser silently
- 📂 **Open File** — open any file on the host silently
- 🔄 **Restart / Shutdown** — manage the SentinelNet process remotely
- 📄 **Log Viewer** — browse and live-refresh log files
- ⏱️ **Uptime / Status** — see host IP, port, version, and uptime

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

## Build from Source

Ensure you have **CMake 3.10+**, a **C++17** compatible compiler (MinGW or MSVC), and **Npcap SDK**.

```bash
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

Place `cloudflared.exe` in the `resources/` folder before building — it gets embedded into the final exe automatically.

---

## Project Links
- **[Live Landing Page](https://sentinelnet.vercel.app)**
- **[Connect Page](https://sentinelnet.vercel.app/connect.html)**
- **[Dashboard Demo](https://sentinelnet.vercel.app/web/dashboard.html)**

---

## License
This project is intended for **educational and personal use only**. Do not use on networks or machines you do not own. The author assumes no liability for misuse.