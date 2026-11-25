<p align="center">
  <img src="docs/brand/readme-banner.png" alt="Bifrost NØX, AI network firewall. Inspect everything. Block only what matters." width="100%">
</p>

<p align="center">
  <img alt="Python 3.11+" src="https://img.shields.io/badge/python-3.11%2B-5E7A8E?style=flat-square&labelColor=1A1714">
  <img alt="Platform: Linux" src="https://img.shields.io/badge/platform-linux-6B8E5A?style=flat-square&labelColor=1A1714">
  <img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-B08A3E?style=flat-square&labelColor=1A1714">
  <img alt="Status: research prototype" src="https://img.shields.io/badge/status-research%20prototype-A85A45?style=flat-square&labelColor=1A1714">
</p>

## What it does

Bifrost NØX is a transparent inspection firewall. It sits between a network and the internet, decrypts and inspects traffic with machine-learning detectors (web attacks, prompt injection, PII and secret leaks, malware in documents, unsafe images) and then allows or blocks it. It fails open by default, so it never gets in the way of normal browsing.

Built as a Final Year Project, it runs behind a Wi-Fi hotspot or in front of a VM lab.

| Dashboard | Block page |
|:---:|:---:|
| <img src="docs/screenshots/dashboard-overview.png" alt="Dashboard overview" width="540"> | <img src="docs/screenshots/block-page.png" alt="Block page served by the firewall" width="338"> |
| Live verdicts, threats, rules and AI file intake | What a user sees, with a request id IT can look up |

## How it works

```
client (phone / laptop / VM)
  │  through a Wi-Fi hotspot or a VM host-only network
  ▼
iptables ──┬── TCP 80/443 ──▶ MITM gateway :8080  (TLS interception)
           │                        │
           │                        ▼
           │                  orchestrator :8000 ──┬──▶ text     :8003
           │                                       ├──▶ image    :8001
           │                                       └──▶ document :8002
           └── DNS / FTP ───▶ C++ NFQUEUE engine ◀── ZeroMQ ──▶ AI brain
```

Every request and response gets an `ALLOW`, `BLOCK` or advisory `CENSOR` verdict, usually in well under a second. The text service runs the WAF, prompt-injection, secret and PII detectors; the image service runs CLIP, YOLOv8, OCR and steganography checks; the document service runs YARA, VirusTotal and structural analysis. Detectors only run where their question makes sense (prompt injection only on traffic bound for an LLM, for example), and low-confidence findings become dashboard warnings rather than blocks. The [detection policy](docs/detection.md) has the details.

## Highlights

- **Transparent TLS inspection.** Per-host certificates from a local CA; QUIC is refused so HTTP/3 cannot slip past.
- **Web-attack detection.** A DistilBERT classifier on request bodies and query values, plus precise signatures (Log4Shell, SSRF, XXE and more).
- **Data-loss prevention.** Vendor secrets and PII (Presidio), judged on evidence rather than entity type.
- **Prompt-injection defence** for traffic going to LLM APIs.
- **Images and documents.** Unsafe-image, OCR and steganography checks; malicious-document scanning.
- **DNS filtering** in a C++ NFQUEUE engine that fails open if its Python brain stops answering.
- **Operator tooling.** Real-time dashboard, rule engine, cert-pinned-app allowlist and a branded block page with request ids.

## Setup

You need a Linux host with iptables (Arch, Debian, Kali and Ubuntu all work), Python 3.11+, Git LFS and about 6 GB of free RAM for the AI services. Clients reach the internet through this host: either a VirtualBox VM on a host-only network, or devices joined to a Wi-Fi hotspot the host runs.

**1. Install the system packages**

```bash
# Arch
sudo pacman -S --needed base-devel python git-lfs tesseract tesseract-data-eng \
    libnetfilter_queue libnfnetlink zeromq cppzmq perl-image-exiftool
# Debian / Kali / Ubuntu
sudo apt install -y build-essential python3-dev python3-venv git-lfs tesseract-ocr \
    libnetfilter-queue-dev libnfnetlink-dev libzmq3-dev libcppzmq-dev libimage-exiftool-perl
```

**2. Get the code and the Python dependencies**

```bash
git lfs install                                  # the WAF model is stored with Git LFS
git clone https://github.com/CYC07/Bifrost-NOX.git && cd Bifrost-NOX
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python -m spacy download en_core_web_lg
```

The other models (CLIP, DeBERTa, YOLOv8, about 2 GB) download automatically the first time the services start.

**3. Build the packet engine and create the certificate authority**

```bash
make -C network_inspector/cpp
(cd gateway && python3 cert_utils.py)            # creates gateway/certs/ca.crt
```

**4. Trust the CA on every client.** Once the firewall is running, download it from `http://<firewall-ip>:8000/ca.crt`, then:

- Windows: `certutil -addstore -f Root ca.crt` (as administrator)
- Android: Settings → Security → Install a certificate → CA certificate
- Linux and macOS: add it to the system (or browser) trust store

## Start

**VM lab (VirtualBox).** Create a host-only network `vboxnet0` (192.168.56.1/24) and give the VM a single adapter on it. Remove any NAT adapter, or the VM's traffic bypasses the firewall. In the VM, use 192.168.56.1 as the gateway and a public DNS server such as 1.1.1.1. Then, on the host:

```bash
./start_services.sh                 # AI services + gateway (no sudo needed)
sudo vm-lab/vm_lab.sh up            # routing, packet engine and DNS filter
```

`vm_lab.sh` reads `UPLINK` (default `wlan0`) for the host's internet interface, and `LAB_IF` / `LAB_IP` if your host-only network differs.

**Wi-Fi hotspot.** Put a Wi-Fi adapter into access-point mode (for example `hostapd` and `dnsmasq` on `wlan1`) with another interface as the uplink, then:

```bash
./start_all.sh                      # services, gateway and network layer (asks for sudo)
```

Either way, the dashboard is at `http://localhost:8000/dashboard/`. To stop:

```bash
sudo vm-lab/vm_lab.sh down && sudo ./stop_all.sh     # VM lab
sudo ./stop_all.sh                                   # hotspot
```

More detail (models, running services by hand, troubleshooting the lab) is in [docs/setup.md](docs/setup.md).

## Configuration

Settings are environment variables (or a `.env` file). The ones most people change:

| Variable | Default | Effect |
|---|---|---|
| `AI_FAIL_MODE` | `open` | `closed` blocks traffic when analysis is unavailable |
| `DOC_SCAN_MODE` | `advisory` | `block` enforces document-scanner verdicts |
| `VIRUSTOTAL_API_KEY` | unset | enables hash lookups for documents |
| `FIREWALL_ADMIN_TOKEN` | unset | allows administration from another machine |
| `BLOCK_REVIEW_URL` | unset | where the block page's "Request a review" button points |

Every setting is listed in [docs/configuration.md](docs/configuration.md).

## Documentation

- **[Setup, running and testing](docs/setup.md)**: installation, models, hotspot and VM lab, dashboard, tests, project layout.
- **[Detection policy](docs/detection.md)**: what runs where, the secret, PII and trusted-domain policies, known limitations.
- **[Configuration](docs/configuration.md)**: every environment variable, the allowlist, VirusTotal, remote administration.

## Tech stack

PyTorch · Hugging Face Transformers (DistilBERT, DeBERTa-v3, CLIP) · YOLOv8 · Tesseract · Presidio · YARA · Starlette · ZeroMQ · C++17 / NFQUEUE · iptables · React 18

## Team

Final Year Project, BS Cyber Security, Riphah International University: Abdur Rafay Naveed, Alian Rafiq and Muhammad Shayan Faisal.

## License

Released under the MIT License.

> **Disclaimer:** a research prototype for controlled lab and hotspot environments, not hardened for production. Intercepting third-party traffic may be restricted where you are: only use it on networks you own or are explicitly allowed to monitor.
