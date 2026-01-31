# Network Watcher

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go)](https://go.dev/)

> **An experimental project exploring the intersection of eBPF, AI-powered security, and modern observability tools.**

<img width="1115" alt="Dashboard Screenshot" src="https://github.com/user-attachments/assets/f29cb54d-dfc2-4d01-b38d-86fef5f2c4a7" />

---

## About This Project

This is a **learning experiment** that combines several cutting-edge technologies:

| Technology | Purpose |
|------------|---------|
| **eBPF** | Kernel-level network monitoring without modifying kernel code |
| **MCP (Model Context Protocol)** | AI tool integration for intelligent analysis |
| **Cilium/eBPF Library** | Go bindings for eBPF program management |
| **Real-time WebSockets** | Live dashboard updates |
| **GeoIP + Threat Intelligence** | Location and risk-based scoring |

### Why This Project?

I built this to learn how modern security tools work under the hood:
- How eBPF intercepts network calls at the kernel level
- How AI can assist in threat detection and analysis
- How to build production-ready observability dashboards
- How tools like Cilium, Falco, and Tetragon approach security

---

## Features

| Feature | Description |
|---------|-------------|
| **eBPF Monitoring** | Kernel-level interception of TCP connections via `kprobe/tcp_connect` |
| **AI Analysis** | Pattern-based threat detection with risk scoring |
| **GeoIP Lookup** | Country/city location for each destination |
| **Risk Scoring** | 0-100 score based on app, port, location |
| **Live Map** | Visual world map of connection destinations |
| **Threat Detection** | Regex patterns for malware, botnets, reverse shells |
| **Whitelist** | One-click whitelisting of trusted apps |
| **Dark/Light Mode** | Theme toggle with localStorage persistence |
| **Export** | JSON and CSV data export |
| **Production Features** | Security headers, rate limiting, health checks |

---

## Quick Start

```bash
# Clone
git clone https://github.com/cxx5208/network-watcher.git
cd network-watcher

# Build (requires clang, llvm, libbpf)
make build

# Run (requires root for eBPF)
sudo ./bin/webui
```

Open **http://localhost:8080**

### For macOS Users

eBPF requires Linux. Use Lima VM:

```bash
brew install lima
limactl start --name=ebpf template://ubuntu
limactl shell ebpf
# Then build and run inside the VM
```

---

## Demo

1. Open the dashboard at `http://localhost:8080`
2. Type `google.com` in the URL input
3. Click **Test** to trigger an unknown app alert
4. Watch the risk score, GeoIP, and map update in real-time
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
┌─────────────────┐     ┌──────────────────┐     ┌─────────────┐
│  Linux Kernel   │     │    User Space    │     │   Browser   │
├─────────────────┤     ├──────────────────┤     ├─────────────┤
│  tcp_connect    │────▶│  eBPF Collector  │     │  Dashboard  │
│    kprobe       │     │        │         │     │      ▲      │
│       │         │     │        ▼         │     │      │      │
│  Perf Buffer    │────▶│   Event Store    │────▶│  WebSocket  │
└─────────────────┘     │        │         │     │      │      │
                        │   Risk Scorer    │     │  Map + List │
                        │        │         │     └─────────────┘
                        │   GeoIP Cache    │
                        └──────────────────┘
```

---

## Risk Scoring Algorithm

| Factor | Points | Reason |
|--------|--------|--------|
| Unknown application | +30 | Not in whitelist of known apps |
| Threat pattern match | +40 | Matches malware/botnet regex |
| High-risk country | +25 | CN, RU, KP, IR destinations |
| Unusual port | +20 | 4444, 5555, 31337, etc. |

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Go 1.23+ |
| eBPF Library | [cilium/ebpf](https://github.com/cilium/ebpf) |
| WebSocket | [gorilla/websocket](https://github.com/gorilla/websocket) |
| GeoIP | [ip-api.com](https://ip-api.com) |
| Frontend | Vanilla JS + CSS |

---

## Project Structure

```
network-watcher/
├── bpf/
│   └── network.c           # eBPF C program (kprobe)
├── cmd/
│   └── webui/
│       └── main.go         # Web server + embedded UI (~940 lines)
├── pkg/
│   ├── collector/          # eBPF loader and event reader
│   ├── store/              # In-memory event storage
│   └── types/              # Data structures and helpers
├── Makefile                # Build automation
└── README.md
```

---

## Inspirations & References

This project was inspired by and learned from these amazing projects:

| Project | What I Learned |
|---------|----------------|
| [Cilium](https://github.com/cilium/cilium) | eBPF-based networking and security |
| [Tetragon](https://github.com/cilium/tetragon) | Runtime security observability with eBPF |
| [Falco](https://github.com/falcosecurity/falco) | Cloud-native runtime security |
| [bcc](https://github.com/iovisor/bcc) | BPF compiler collection and examples |
| [ebpf-go](https://github.com/cilium/ebpf) | Pure Go eBPF library |
| [Pixie](https://github.com/pixie-io/pixie) | Observability with eBPF |
| [MCP Protocol](https://modelcontextprotocol.io/) | AI tool integration patterns |

### Learning Resources

- [eBPF.io](https://ebpf.io/) - Official eBPF documentation
- [Brendan Gregg's Blog](https://www.brendangregg.com/ebpf.html) - eBPF performance analysis
- [Isovalent Labs](https://isovalent.com/labs/) - Hands-on eBPF tutorials
- [Cilium Documentation](https://docs.cilium.io/) - Production eBPF usage

---

## Limitations & Future Ideas

This is an experiment, not production software. Known limitations:

- **IPv4 only** - No IPv6 support yet
- **TCP only** - No UDP/ICMP monitoring
- **No persistence** - Data is in-memory only
- **Basic threat rules** - Simple regex patterns

Future explorations:
- [ ] Add eBPF tracepoints for file access monitoring
- [ ] Integrate with actual LLM for smarter analysis
- [ ] Add Prometheus metrics export
- [ ] Container-aware process tracking
- [ ] eBPF-based DNS query monitoring

---

## Requirements

- Linux kernel 5.4+ with BTF support
- Go 1.23+
- Clang/LLVM (for eBPF compilation)
- Root privileges (for eBPF)

---

## License

MIT License - see [LICENSE](LICENSE)

---

## Contributing

This is a learning project, but contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md).

---

*Built as a portfolio project to explore eBPF, AI tools, and modern security observability.*
