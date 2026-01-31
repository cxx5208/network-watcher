# Network Watcher

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go)](https://go.dev/)

**Real-time network security monitoring using eBPF and AI-powered threat detection.**

<img width="1115" height="759" alt="Screenshot 2026-01-30 at 7 37 11 PM" src="https://github.com/user-attachments/assets/f29cb54d-dfc2-4d01-b38d-86fef5f2c4a7" />


---

## Features

| Feature | Description |
|---------|-------------|
| **eBPF Monitoring** | Kernel-level interception of TCP connections |
| **GeoIP Lookup** | Shows country/city for each destination |
| **Risk Scoring** | 0-100 score based on app, port, location |
| **Live Map** | Visual world map of connection destinations |
| **Threat Detection** | Pattern matching for malware, botnets, shells |
| **Whitelist** | One-click whitelisting of trusted apps |
| **Dark/Light Mode** | Theme toggle with persistence |
| **Keyboard Shortcuts** | Power-user navigation (F, R, E, T, ?) |
| **Export** | JSON and CSV data export |
| **Production Ready** | Security headers, rate limiting, health checks |

---

## Quick Start

```bash
# Clone
git clone https://github.com/cxx5208/network-watcher.git
cd network-watcher

# Build (requires clang, llvm)
make build

# Run (requires root for eBPF)
sudo ./bin/webui
```

Open **http://localhost:8080**

---

## Demo

1. Open the dashboard
2. Type `google.com` in the URL input
3. Click **Test** to trigger an unknown app alert
4. Watch the risk score, GeoIP, and map update
5. Click **Whitelist** to mark as trusted

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `F` | Focus URL input |
| `R` | Refresh page |
| `E` | Export JSON |
| `T` | Toggle theme |
| `?` | Show shortcuts |

---

## Architecture

```
Linux Kernel          User Space              Browser
+-------------+      +--------------+      +------------+
| tcp_connect |----->| Collector    |      | Dashboard  |
|   kprobe    |      |      |       |      |     ^      |
|      |      |      |      v       |      |     |      |
| Perf Buffer |----->| Event Store  |----->| WebSocket  |
+-------------+      |      |       |      |     |      |
                     | Risk Scorer  |      | Map + List |
                     |      |       |      +------------+
                     | GeoIP Cache  |
                     +--------------+
```

---

## Risk Scoring

| Factor | Points |
|--------|--------|
| Unknown application | +30 |
| Threat pattern match | +40 |
| High-risk country (CN, RU, KP, IR) | +25 |
| Unusual port (4444, 5555, 31337) | +20 |

---

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Web dashboard |
| `GET /health` | Health check |
| `GET /api/data` | Monitoring data |
| `GET /api/fetch?url=&mode=` | Trigger URL fetch |
| `GET /api/whitelist?app=` | Whitelist an app |
| `GET /api/export/json` | Export JSON |
| `GET /api/export/csv` | Export CSV |
| `WS /ws` | Real-time events |

---

## Project Structure

```
network-watcher/
├── bpf/network.c           # eBPF program
├── cmd/webui/main.go       # Web server + UI (~900 lines)
├── pkg/
│   ├── collector/          # eBPF loader
│   ├── store/              # Event storage
│   └── types/              # Data types
├── .github/workflows/      # CI/CD
└── Makefile
```

---

## Tech Stack

- **Go** - Backend server
- **eBPF** - Kernel-level monitoring
- **WebSocket** - Real-time updates
- **Three.js** - (Optional) 3D effects
- **ip-api.com** - GeoIP lookup

---

## Requirements

- Linux kernel 5.4+ with BTF support
- Go 1.23+
- Clang/LLVM
- Root privileges

---

## License

MIT License - see [LICENSE](LICENSE)
