# Bifrost NØX — AI-Driven Network Firewall

![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge&logo=opensourceinitiative&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![PyTorch](https://img.shields.io/badge/PyTorch-EE4C2C?style=for-the-badge&logo=pytorch&logoColor=white)
![React](https://img.shields.io/badge/React_18-61DAFB?style=for-the-badge&logo=react&logoColor=black)
![C++](https://img.shields.io/badge/C++-17-00599C?style=for-the-badge&logo=cplusplus&logoColor=white)
![Status](https://img.shields.io/badge/Status-In_Development-orange?style=for-the-badge)

An AI-powered transparent proxy firewall that intercepts, inspects, and classifies network traffic in real time using a multi-layered pipeline of specialised machine learning microservices. Built as a Final Year Project.

---

## Overview

Bifrost NØX sits between a Wi-Fi hotspot and the internet, intercepting HTTP and HTTPS traffic via a MITM proxy and iptables packet capture. Each request is analysed by one or more AI microservices — image classification, document scanning, and NLP — before a ALLOW / BLOCK / CENSOR verdict is returned in milliseconds.

```
Device (phone/laptop)
        │
        ▼
  Wi-Fi Hotspot (wlan1)
        │  iptables REDIRECT / NFQUEUE
        ▼
  C++ Firewall Engine  ◄──ZeroMQ IPC──►  AI Brain (Python)
        │                                        │
        ▼                                        ▼
  MITM Gateway (:8080)              Master AI Orchestrator (:8000)
  TLS interception                  ┌─────────────────────────┐
  SNI extraction                    │  Image Service  (:8001)  │
  Allowlist bypass                  │  Document Service(:8002) │
                                    │  Text Service   (:8003)  │
                                    └─────────────────────────┘
                                              │
                                              ▼
                                    Dashboard (localhost:8000)
```

---

## Features

- **Transparent HTTPS interception** — MITM proxy with per-domain certificate generation; no client configuration needed when deployed as a hotspot gateway
- **AI content analysis** — CLIP + YOLOv8 for image NSFW/object detection; YARA + metadata heuristics for documents; Presidio + sentence-transformers for PII, API key leaks, and SQL injection in text
- **Static rule engine** — IP/port/domain/keyword rules evaluated before AI inference; configurable via the dashboard
- **Allowlist for cert-pinned apps** — WhatsApp, Snapchat, Signal, Telegram, and any other app that pins its TLS certificate can be allowlisted to tunnel through uninspected; all others are blocked by default if MITM fails
- **Real-time dashboard** — live KPI cards, threat feed, traffic charts, rule management, and AI file intake at `http://localhost:8000`
- **C++ packet engine** — NFQUEUE handler with 10-second flow cache; fail-open by default so network access is never fully blocked

---

## Architecture

| Layer | Component | Port / IPC |
|---|---|---|
| Packet capture | `network_inspector/cpp/firewall_engine` | NFQUEUE 1 |
| AI bridge | `network_inspector/ai_brain.py` | ZMQ `ipc:///tmp/firewall_pipeline` |
| MITM proxy | `gateway/proxy.py` + `mitm_engine.py` | :8080 |
| Orchestrator | `master_ai/orchestrator.py` | :8000 |
| Image AI | `image_service/main.py` | :8001 |
| Document AI | `document_service/main.py` | :8002 |
| Text AI | `text_service/main.py` | :8003 |
| Dashboard | `dashboard/` | served at `/` by orchestrator |

---

## Installation

```bash
git clone https://github.com/CYC07/Bifrost-NOX.git
cd Bifrost-NOX

# 1. System dependencies (Debian / Kali / Ubuntu)
sudo apt update && sudo apt install -y \
    tesseract-ocr \
    libnetfilter-queue-dev \
    build-essential \
    g++ \
    libzmq3-dev \
    python3-dev \
    python3-venv

# 2. Generate the local CA certificate (required for HTTPS interception)
cd gateway && python3 cert_utils.py && cd ..
```

---

## Running

### Full stack (hotspot mode)

Requires a Wi-Fi adapter in AP mode (`wlan1`). Start the hotspot first, then:

```bash
source venv/bin/activate
./start_all.sh
```

### Gateway + AI services only (no hotspot)

To inspect traffic on the local machine or route traffic manually:

```bash
source venv/bin/activate

# Terminal 1 — AI microservices
uvicorn master_ai.orchestrator:app --host 0.0.0.0 --port 8000 &
uvicorn image_service.main:app --host 0.0.0.0 --port 8001 &
uvicorn document_service.main:app --host 0.0.0.0 --port 8002 &
uvicorn text_service.main:app --host 0.0.0.0 --port 8003 &

# Terminal 2 — MITM proxy
python3 gateway/proxy.py
```

Then set your browser or system proxy to `127.0.0.1:8080`.

### Stop everything

```bash
sudo ./stop_all.sh
```

---

## Dashboard

Open `http://localhost:8000` in your browser after starting the stack.

| Page | Description |
|---|---|
| Overview | Live KPI cards, threat feed, blocked event chart |
| Traffic | Throughput graphs, protocol breakdown, recent flows |
| Rules & Policies | Static rule engine — add/remove IP, port, domain, keyword rules; manage the app allowlist |
| Threats | AI-classified threat log with severity and confidence |
| Logs | Raw event stream from all services |
| Devices | Health status of all AI microservices |
| Reports | Session summaries and export |
| AI Intake | Drag-and-drop file analysis (images, PDFs, documents) |

---

## Allowlist (cert-pinned apps)

Apps like WhatsApp, Snapchat, Signal, and Telegram pin their TLS certificates and will reject the proxy's locally-signed certificate. Without an allowlist entry, these connections are **blocked by default** and logged as `PINNED-TLS` on the dashboard.

To allow them through without inspection, add the host pattern on the **Rules & Policies** page using the Allowlist panel, or via the API:

```bash
# Add a host
curl -X POST http://localhost:8000/allowlist \
  -H "Content-Type: application/json" \
  -d '{"host": "*.whatsapp.net"}'

# List allowlisted hosts
curl http://localhost:8000/allowlist

# Remove a host
curl -X DELETE http://localhost:8000/allowlist/*.whatsapp.net
```

Preset buttons for WhatsApp, Snapchat, Signal, Telegram, and iMessage are available in the dashboard.

---

## Network Topology (hotspot mode)

| Item | Value |
|---|---|
| Hotspot SSID | FYP-AI-Firewall |
| Subnet | 192.168.50.0/24 |
| Gateway | 192.168.50.1 |
| Proxy port | 8080 |
| Internet uplink | `eth0` or USB tether |

---

## Project Structure

```
ai_firewall/
├── common/               # Shared schemas, utilities, allowlist module
├── config/               # Persisted rules and allowlist (JSON)
├── dashboard/            # React 18 + Babel frontend (served by orchestrator)
├── document_service/     # YARA, metadata, structure analysis
├── gateway/              # MITM proxy, TLS engine, certificate authority
├── image_service/        # CLIP, YOLOv8, Tesseract OCR
├── master_ai/            # Orchestrator, rule engine
├── network_inspector/    # C++ NFQUEUE engine + Python ZMQ bridge
├── text_service/         # Presidio PII, sentence-transformers, SQLi
├── start_all.sh          # Start full stack
├── start_network.sh      # iptables + C++ engine + AI brain
├── stop_all.sh           # Stop everything
└── requirements.txt
```

---

## Tech Stack

**AI / ML:** PyTorch · CLIP · YOLOv8 (ultralytics) · Tesseract OCR · sentence-transformers · Presidio · YARA · scikit-learn

**Backend:** Python 3.11 · Starlette · uvicorn · httpx · ZeroMQ · cryptography

**Network:** iptables · NFQUEUE · C++17 · libnetfilter-queue · Scapy

**Frontend:** React 18 · Babel standalone · custom CSS design system (no framework)

---

## License

MIT — see `LICENSE` for details.

> **Disclaimer:** This project is a research prototype built for a controlled lab/hotspot environment. It is not hardened for production deployment. MITM inspection of third-party traffic may be subject to legal restrictions in your jurisdiction — only use on networks you own or have explicit permission to monitor.
