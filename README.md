# SentinelNet v2.0

SentinelNet is a self-hosted network security tool designed for home labs and enterprise auditing. It combines a powerful **C++17 parallel-scanning engine** with a modern web dashboard for real-time visibility.

---

## What's New in v2.0
- **High-Speed Multi-threading**: Port scans are now up to **10x faster** using hardware-accelerated concurrency.
- **Professional Interactive Shell**: A redesigned CLI shell for complex auditing without leaving your terminal.
- **Security Scoring**: Improved anomaly detection for rogue access points and suspicious device behavior.
- **Network Discovery**: Blazingly fast device discovery using CIDR and IP range expansion.

---

## Quick Start (Portable)

You can run SentinelNet as a portable tool without building the source.

1.  **Download**: Get the latest release from the [Live Landing Page](https://sentinelnet.vercel.app/).
2.  **Extract**: Unzip the folder (ensure the `web/` folder stays with the `.exe`).
3.  **Launch**:
    - **Dashboard**: Run `.\SentinelNet.exe -D` to start the web UI at `http://localhost:8080`.
    - **Interactive Shell**: Run `.\SentinelNet.exe` (no arguments) to enter the security shell.

---

## Project Links
- **[Live Landing Page](https://sentinelnet.vercel.app)**
- **[Interactive Dashboard Demo](https://sentinelnet.vercel.app/dashboard.html)**

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