# NetScope — Network Traffic Analyzer & Anomaly Detector

A command-line tool that captures network traffic, computes live statistics
(protocol mix, top talkers, bandwidth, busiest conversations), and flags
security anomalies such as **port scans** and **SYN floods** using explainable,
windowed heuristics.

Built in pure Python with a clean, testable pipeline:

```
packet source  ->  PacketRecord  ->  TrafficAnalyzer  (stats)
(live/pcap/sim)                  \->  DetectorPipeline (alerts)  ->  Reporter (console/JSON/CSV)
```

## Why this project

It mirrors the kind of network observability and security tooling used in
real infrastructure: deep-packet inspection, flow accounting, and intrusion
detection. The architecture deliberately decouples capture from analysis so the
same engine works on a **live interface**, a **saved `.pcap`**, or **synthetic
traffic** — the last of which means it's fully demoable with zero setup.

## Features

- **Three capture backends** — live sniffing (Scapy), offline `.pcap` replay,
  and a built-in synthetic generator with embedded attacks.
- **Streaming statistics** — O(1)-per-packet aggregation of protocol
  distribution, top talkers/destinations, per-flow conversations, destination
  port usage, and a per-second throughput timeline (avg + peak bps).
- **Anomaly detection** — sliding-window **port-scan** and **SYN-flood**
  detectors that emit severity-tagged alerts.
- **Rich reporting** — color terminal tables (via `rich`, with a plain-text
  fallback) plus **JSON** (full summary + alerts) and **CSV** (flow table) export.

## Quick start

```bash
pip install -r requirements.txt

# Zero-setup demo: synthetic traffic containing a port scan + SYN flood
python -m netscope.cli --demo

# Save reports
python -m netscope.cli --demo --json report.json --csv flows.csv
```

Sample demo output:

```
=== NetScope - Capture Overview ===
Total packets : 400
Total volume  : 253.6 KB
Avg throughput: 488.0 Kbps

--- Security Alerts ---
  [HIGH] port_scan: 192.168.1.66 probed 15 distinct ports on 10.0.0.1 within 5s
  [HIGH] syn_flood: 30 half-open SYNs to 10.0.0.1 within 3s (possible SYN flood)
```

## Usage

```bash
# Analyze a saved capture
python -m netscope.cli --pcap traffic.pcap --json report.json

# Sniff a live interface (needs root/admin), with a BPF filter, capped at 500 pkts
sudo python -m netscope.cli --iface en0 --filter "tcp port 443" --count 500
```

| Flag | Description |
|------|-------------|
| `--demo` | Run on synthetic traffic (no privileges/network needed) |
| `--iface IFACE` | Sniff a live interface (requires Scapy + privileges) |
| `--pcap FILE` | Analyze a `.pcap` / `.pcapng` file |
| `--count N` | Max packets to process |
| `--filter BPF` | BPF capture filter for live mode |
| `--json FILE` / `--csv FILE` | Export report / flow table |

## Project layout

```
netscope/
  models.py      # PacketRecord: library-agnostic packet view
  capture.py     # Live / pcap / simulated packet sources
  analyzer.py    # Streaming traffic statistics engine
  detectors.py   # Port-scan & SYN-flood detectors + pipeline
  reporter.py    # Rich console tables + JSON/CSV export
  cli.py         # argparse entry point
```

## Tests

A `pytest` suite covers the detectors (threshold firing, time-window aging,
fire-once semantics, protocol filtering) and the statistics engine
(byte/packet accounting, direction-agnostic flows, throughput math):

```bash
pip install -r requirements-dev.txt
pytest            # 16 tests
```

## How detection works

- **Port scan** — per `(source, destination)` pair, track distinct destination
  ports seen within a 5-second sliding window; alert when one source touches
  ≥15 distinct ports (classic horizontal scan signature).
- **SYN flood** — per destination, count TCP packets with SYN set but ACK clear
  (half-open handshakes) within a 3-second window; alert past 30.

Thresholds and windows are constructor parameters, so they're easy to tune.

## Resume bullet points

> - Built **NetScope**, a Python network traffic analyzer with three
>   interchangeable capture backends (live Scapy sniffing, `.pcap` replay, and a
>   synthetic generator) feeding a streaming statistics engine that reports
>   protocol distribution, top talkers, per-flow conversations, and avg/peak
>   throughput.
> - Implemented sliding-window intrusion-detection heuristics that flag **port
>   scans** and **SYN-flood** attacks, emitting severity-tagged alerts exported
>   to JSON/CSV.
> - Designed a decoupled `PacketRecord` abstraction so the analysis and
>   detection pipeline is unit-testable and runs without root access; wrote a
>   16-case **pytest** suite covering detector thresholds, time-window aging,
>   and flow accounting.

## Tech stack

Python 3 · Scapy · Rich · argparse · dataclasses
