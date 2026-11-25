# Configuration

Every setting, the cert-pinned-app allowlist, VirusTotal and remote administration. Back to the [README](../README.md).

All settings are environment variables. `start_all.sh` sources a `.env` in the project root if present; when starting services by hand, `set -a; source .env; set +a` first.

| Variable | Default | Meaning |
|---|---|---|
| `AI_FAIL_MODE` | `open` | what to do when no verdict arrives: `open` allows, `closed` blocks (gateway **and** orchestrator) |
| `AI_TIMEOUT` | `10.0` | seconds the gateway waits for a text/document verdict |
| `AI_TIMEOUT_IMAGE` | `40.0` | seconds the gateway waits for an image verdict (images queue behind each other during a burst) |
| `SERVICE_TIMEOUT` | `8.0` | seconds the orchestrator waits for each analysis service (keep below `AI_TIMEOUT`) |
| `IMAGE_SERVICE_TIMEOUT` | `30.0` | seconds the orchestrator waits for the image service (keep below `AI_TIMEOUT_IMAGE`) |
| `BLOCK_QUIC` | `1` | `start_network.sh` refuses UDP 443 from clients so browsers fall back from QUIC/HTTP/3 to TCP, which the firewall inspects. Without it, a browser that has learned a site supports HTTP/3 (Google does) bypasses inspection entirely. `0` = off |
| `UPSTREAM_CONNECT_TIMEOUT` | `5.0` | seconds the gateway waits per attempt to connect to the real server; on failure the client gets a `502` page and an `UPSTREAM-FAIL` event |
| `UPSTREAM_CONNECT_RETRIES` | `1` | extra connect attempts after a timeout or transient network error (a refused connection is not retried) |
| `BLOCK_REVIEW_URL` | unset | `mailto:` or `https:` link behind the block page's "Request a review" button (e.g. your IT Security mailbox). Unset, the button copies the request id, which is also written to `gateway.log` (`Block page served: id=nox-...`) |
| `BRAIN_TIMEOUT_MS` | `1500` | C++ engine: how long to wait for the AI brain's DNS/FTP verdict before giving up |
| `BRAIN_COOLDOWN_MS` | `3000` | C++ engine: after the brain fails, skip it this long (no per-packet waiting) and then try again |
| `BRAIN_FAIL_MODE` | `open` | C++ engine: `open` accepts DNS/FTP packets while the brain is down, `closed` drops them |
| `TEXT_MAX_CONCURRENCY` | `2` | concurrent text analyses (worker threads) |
| `TEXT_CACHE_SIZE` | `2048` | verdict cache entries (identical bodies are analysed once) |
| `WAF_ATTACK_THRESHOLD` | `0.99` | text-service block cutoff for the WAF (shipped v3 model) |
| `WAF_MAX_VALUES` / `WAF_MAX_VALUE_CHARS` | `64` / `2000` | caps for per-value scoring |
| `WAF_MODEL_PATH` | `ml/waf/artifacts/waf_distilbert` | joblib file or HF directory |
| `PROMPT_INJECTION_THRESHOLD` | `0.9` | injection-model block cutoff (LLM traffic only) |
| `PII_MIN_SCORE` | `0.4` | minimum Presidio confidence for an SSN/IBAN/card match to count |
| `WAF_SIGNATURES` | `block` | extra attack classes (SSRF, XXE, CRLF, NoSQLi, JNDI, deserialization, ...): `block`, `advisory`, `off` |
| `SCANNER_BEHAVIOUR_POLICY` | `block` | client+host that mostly gets 404/403 across many paths (a scan, whatever its User-Agent): `block` for a 5-minute cooldown, `advisory` (log only), `off` |
| `SCANNER_UA_POLICY` | `block` | known scanner/exploit tool in the User-Agent: `block`, `advisory` (log only), `off` |
| `DOC_SCAN_MODE` | `advisory` | `advisory` (document-service block shown as a warning), `block` (enforce), `off` (legacy route) |
| `DOC_SCAN_MAX_BYTES` | `20971520` | documents larger than this are allowed unanalysed |
| `TRUSTED_VERIFY_IP` | `1` | require a trusted-domain connection to land in Microsoft's IP ranges (`0` = name-only) |
| `SENSITIVE_THRESHOLD` / `SENSITIVE_LABELS` | `0.6` / built-in | zero-shot sensitive-content cutoff / label override |
| `IMAGE_MAX_CONCURRENCY` | `2` | images analysed at once by the image service (OCR, object detection, steganography and CLIP together); the rest queue |
| `IMAGE_CACHE_SIZE` | `512` | image verdicts remembered by SHA-256 of the image (`0` = off) |
| `IMAGE_MIN_ANALYSIS_BYTES`, `IMAGE_MIN_PIXELS` | `4096`, `4096` | images smaller than either skip the models (icons, trackers) and get the file-safety check only; `0` turns each off |
| `IMAGE_OCR_MAX_FRAMES`, `IMAGE_CLIP_MULTICROP`, `IMAGE_STEGO_STRICT` | `8`, off, off | image-service tuning |
| `HOTSPOT_IF` / `INTERNET_IF` | `wlan1` / other wlan | interfaces used by the start/stop scripts |
| `PROXY_BIND_IP` | auto | override the proxy bind address |
| `VIRUSTOTAL_API_KEY` | – | enables hash lookups in the document service |
| `FIREWALL_ADMIN_TOKEN` | – | remote administration token (see below) |

Edit `config/llm_hosts.json` (`hosts` and `paths`) to change what counts as LLM traffic; `config/allowed_apps.json` for cert-pinned apps; `config/dns_blocklist.json` for DNS filtering.

## Allowlist (cert-pinned apps)

Apps like WhatsApp, Snapchat, Signal, and Telegram pin their TLS certificates and reject the proxy's locally-signed certificate. Without an allowlist entry these connections are **blocked** and logged as `PINNED-TLS`. (If the site itself is unreachable from the firewall you get a `502` page and an `UPSTREAM-FAIL` event instead: that is a network problem, not pinning, and allowlisting will not help.) Add the host pattern from **Rules & Policies**, or via the API:

```bash
curl -X POST http://localhost:8000/allowlist -H "Content-Type: application/json" -d '{"host": "*.whatsapp.net"}'
curl http://localhost:8000/allowlist
curl -X DELETE http://localhost:8000/allowlist/*.whatsapp.net
```

## VirusTotal integration

The document service hashes every scanned file (SHA-256) and queries VirusTotal. No file bytes are uploaded. With no key set the service runs YARA-only.

| Scenario | Score | Verdict |
|---|---|---|
| VT reports ≥ 1 malicious engine | 0.99 | BLOCK |
| 0 detections / not found / API unavailable | 0.0 | pass to YARA |

```bash
echo "VIRUSTOTAL_API_KEY=your_key_here" >> .env     # .env is gitignored
```

## Control-plane authentication

The orchestrator on `:8000` is reachable by clients, so admin actions are gated: `POST/DELETE /rules`, `/allowlist`, `/test_attack` and the internal ingest endpoints (`/analyze_traffic`, `/log_event`) accept only a **loopback client** or a valid admin token. Read-only dashboard GETs stay open.

```bash
echo "FIREWALL_ADMIN_TOKEN=$(openssl rand -hex 24)" >> .env
curl -X POST http://<firewall-ip>:8000/allowlist \
  -H "X-Admin-Token: $FIREWALL_ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"host": "*.example.com"}'
```
