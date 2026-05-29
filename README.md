<p align="center">
  <img src="docs/netocto.jpg" width="350">
  <img src="docs/masked.jpg" width="350">
</p>


# SDN Federated Anomaly Detection — Human-in-the-Loop Security

A four-tool security system for Software-Defined Networks that combines
federated machine learning, poisoning defense, control-plane attack simulation,
and human-centered threat response.

---

## Table of contents

1. [Project overview](#project-overview)
2. [Repository structure](#repository-structure)
3. [Network topology](#network-topology)
4. [Installation](#installation)
5. [Tool 1 — Federated anomaly detection](#tool-1--federated-anomaly-detection)
6. [Tool 2 — Byzantine-robust poisoning defense](#tool-2--byzantine-robust-poisoning-defense)
7. [Tool 3 — OpenFlow FlowMod injection](#tool-3--openflow-flowmod-injection)
8. [Tool 4 — Human-in-the-Loop security dashboard](#tool-4--human-in-the-loop-security-dashboard)
9. [Full pipeline reference](#full-pipeline-reference)
10. [Makefile targets](#makefile-targets)
11. [Configuration](#configuration)
12. [Running tests](#running-tests)
13. [Limitations and known issues](#limitations-and-known-issues)

---

## Project overview

| Tool | What it does | Key files |
|------|-------------|-----------|
| **Tool 1** | Train Isolation Forest models per switch client, federate them into one global anomaly detector | `src/local_train.py`, `src/federated.py`, `src/detect.py` |
| **Tool 2** | Defend federated aggregation against model poisoning using Z-score sanitization | `src/sanitizer.py`, `sdn_mininet/poisoned_host.py` |
| **Tool 3** | Demonstrate a control-plane attack: sniff the unencrypted OpenFlow channel, inject a rogue FlowMod DROP rule | `sdn_mininet/injector.py` |
| **Tool 4** | Human-in-the-Loop dashboard: explain why a flow is suspicious, let the operator review it, then install a defensive DROP rule | `src/hitl.py`, `src/explainer.py`, `sdn_mininet/mitigator.py`, `dashboard/` |

The project runs on **Ubuntu 20.04** with **Python 3.10**, **Mininet 2.3.1b4**, and **Ryu 4.34**.

---

## Repository structure

```
.
├── cli.py                        # Root CLI — all four tools
├── Makefile                      # One-command reproducibility
├── requirements.txt
├── install.sh                    # Ubuntu 20.04 system setup
├── config/
│   ├── fed_config.yaml           # FL simulation parameters (Tools 1–2)
│   └── hitl_config.yaml          # HITL thresholds and demo scenarios (Tool 4)
├── src/
│   ├── __init__.py
│   ├── features.py               # Flow feature extraction + preprocessing
│   ├── local_train.py            # Isolation Forest training (Tool 1)
│   ├── federated.py              # Federated aggregation (Tools 1–2)
│   ├── detect.py                 # Anomaly scoring engine (Tool 1)
│   ├── evaluate.py               # Metrics + confusion matrix (Tools 1–2)
│   ├── sanitizer.py              # Z-score poisoning defense (Tool 2)
│   ├── hitl.py                   # Alert dataclass + AlertQueue (Tool 4)
│   └── explainer.py              # Human-readable alert text (Tool 4)
├── sdn_mininet/
│   ├── topology.py               # Mininet topology (three switches, seven hosts)
│   ├── ryu_collector.py          # Ryu controller + flow stats CSV writer
│   ├── poisoned_host.py          # Tool 2 attack: upload inflated metric
│   ├── injector.py               # Tool 3 attack: raw OpenFlow FlowMod injection
│   ├── label_window.py           # Post-run CSV labeling by timestamp
│   └── mitigator.py              # Tool 4: install / remove DROP rules
├── dashboard/
│   ├── app.py                    # Flask REST API server (port 5000)
│   ├── templates/index.html      # Operator web UI
│   └── static/dashboard.js      # Live polling, decision flow, keyboard nav
├── scripts/
│   └── generate_data.py          # Synthetic flow data generator
├── data/                         # Generated CSVs (git-ignored)
├── models/                       # Trained model bundles (git-ignored)
├── results/                      # Evaluation output + audit logs (git-ignored)
├── tests/
│   └── test_sanitizer.py         # Tool 2 unit tests
└── docs/                         # Architecture diagrams (.drawio.svg)
```

---

## Network topology

```
          Ryu Controller (port 6633)
                   |
        ┌──────────┴──────────┐
        s1 (dpid=1)           |
       /  \                   |
     h1    h2 ←── HTTP :80    |
     h7 (Tool 3 injector)     |
        |                     |
        s2 (dpid=2)           |
       /  \                   |
     h3    h4 ←── DDoS (hping3)
        |
        s3 (dpid=3)
       /  \
     h5    h6 ←── Port scan (nmap) / FL poisoner
```

| Host | Role | Switch | IP |
|------|------|--------|----|
| h1 | Benign client (HTTP, iperf3) | s1 | 10.0.0.1 |
| h2 | HTTP server (port 80 + 8080) | s1 | 10.0.0.2 |
| h3 | Benign client (UDP, HTTP) | s2 | 10.0.0.3 |
| h4 | DDoS attacker (hping3 SYN flood) | s2 | 10.0.0.4 |
| h5 | Benign client (ping keepalive) | s3 | 10.0.0.5 |
| h6 | Port scanner / FL model poisoner | s3 | 10.0.0.6 |
| h7 | FlowMod injector (Tool 3) | s1 | 10.0.0.7 |

---

## Installation

### Prerequisites

Ubuntu 20.04 (native or VM). The lab does not work inside Docker for the live
Mininet mode because Mininet requires kernel namespaces.

### Automated setup

```bash
chmod +x install.sh
./install.sh
```

This installs Open vSwitch, Mininet from source (Python 3), the Ryu SDN
framework, hping3, nmap, iperf3, and all Python dependencies.

### Manual Python dependencies

```bash
pip3 install -r requirements.txt
```

Tool 4 requires Flask (not included in the base Ryu environment):

```bash
pip3 install flask flask-cors
```

### Verify the install

```bash
# Mininet
sudo python3 -c "import mininet; print('Mininet OK')"

# Ryu
ryu-manager --version

# Python packages
python3 -c "import sklearn, flask, scapy; print('All OK')"
```

---

## Tool 1 — Federated anomaly detection

Tool 1 trains an Isolation Forest on each switch's flow data independently,
then federates the models into a single global anomaly detector without sharing
raw traffic. Detection runs against the federated model rather than any
individual client's data.

### Offline demo (no Mininet needed)

```bash
# 1. Generate synthetic flow data for three clients
python3 cli.py generate-data --n-clients 3 --n-benign 2000 --n-attack 400

# 2. Train one local model per client
python3 cli.py train --data data/client1.csv --client-id client1 --out models/client1.pkl
python3 cli.py train --data data/client2.csv --client-id client2 --out models/client2.pkl
python3 cli.py train --data data/client3.csv --client-id client3 --out models/client3.pkl

# 3. Federate into one global model
python3 cli.py federate --models "models/client*.pkl" --out models/global.pkl

# 4. Score new flows
python3 cli.py detect --model models/global.pkl --data data/new_flows.csv --top-n 10

# 5. Evaluate against labeled test data
python3 cli.py evaluate --model models/global.pkl \
    --detections results/detections.csv \
    --data data/test_labeled.csv \
    --local-models "models/client*.pkl" \
    --out results/
```

Or run the entire pipeline in one command:

```bash
make all
```

### Live Mininet mode

```bash
# Terminal 1 — Ryu controller
ryu-manager sdn_mininet/ryu_collector.py --observe-links

# Terminal 2 — Mininet topology (benign traffic only)
sudo python3 sdn_mininet/topology.py --time 120

# Terminal 3 — watch CSVs grow
watch -n 5 wc -l data/live_client*.csv

# After collection — train on live data
python3 cli.py train --data data/live_client1.csv --client-id live_c1 --out models/live_c1.pkl
python3 cli.py train --data data/live_client2.csv --client-id live_c2 --out models/live_c2.pkl
python3 cli.py train --data data/live_client3.csv --client-id live_c3 --out models/live_c3.pkl
python3 cli.py federate --models "models/live_*.pkl" --out models/live_global.pkl
python3 cli.py detect   --model models/live_global.pkl --data data/live_client2.csv --top-n 10
```

### How it works

The Ryu controller polls every switch every 5 seconds for flow statistics
using `OFPFlowStatsRequest`. Each switch's statistics are written to
`data/live_clientN.csv`. The Isolation Forest learns the normal traffic
distribution for each client independently (no labels used during training).
At inference time, flows are scored using the federated ensemble: each
client's model scores the flow, and the scores are averaged. Flows with
scores below the consensus threshold are flagged as anomalous.

---

## Tool 2 — Byzantine-robust poisoning defense

Tool 2 defends the federated aggregation step against model poisoning attacks.
A compromised host (h6) uploads a grossly inflated metric designed to push the
global model away from the legitimate consensus. The Z-score sanitizer detects
and removes the outlier before aggregation.

### Run the poisoning demo

```bash
# Terminal 1 — Ryu controller
ryu-manager sdn_mininet/ryu_collector.py --observe-links

# Terminal 2 — Mininet topology
sudo python3 sdn_mininet/topology.py --time 120 --attack

# Terminal 3 — legitimate clients upload healthy metrics
python3 sdn_mininet/poisoned_host.py --host h1 --no-poison --controller-ip 127.0.0.1
python3 sdn_mininet/poisoned_host.py --host h2 --no-poison --controller-ip 127.0.0.1

# Terminal 4 — attacker uploads poisoned metric (100× multiplier)
python3 sdn_mininet/poisoned_host.py --host h6 --multiplier 100 --controller-ip 127.0.0.1

# Trigger aggregation — watch sanitizer reject h6
curl http://127.0.0.1:8080/fl/aggregate
```

### Standalone demo (no Mininet)

```bash
python3 cli.py demo
```

### Multi-round FL simulation

```bash
python3 cli.py simulate-fl --config config/fed_config.yaml --poison h6:100
```

### Z-score sanitizer

The sanitizer computes the group mean and standard deviation across all client
uploads, then calculates the Z-score for each client. Clients with
`|Z| > threshold` (default 1.5 for small groups, 2.0 for larger) are rejected
before aggregation. The threshold is configurable in `config/fed_config.yaml`
and via the `Z_THRESHOLD` environment variable.

---

## Tool 3 — OpenFlow FlowMod injection

Tool 3 demonstrates that an adversary with access to the host machine can
observe the unencrypted OpenFlow control channel and inject malicious flow
rules directly into a switch — bypassing the Ryu controller entirely.

### How the attack works

**Phase 1 — Passive sniff:** `injector.py` listens on the loopback interface
for OpenFlow traffic on port 6633. When the Ryu controller sends a message to
s1, the sniffer fires.

**Phase 2 — FlowMod injection:** The injector connects directly to s1's passive
OVS listener (`ptcp:6654`), performs an OpenFlow 1.3 handshake, requests
`EQUAL` role, and sends a crafted `OFPFlowMod` that drops all TCP traffic
destined for port 80 with priority 40000.

**Evasion:** The rule matches only `tcp_dst=80`. ICMP (ping) traffic is never
matched, so `h1 ping h2` continues to succeed while `h1 curl h2` times out.

### Run the attack

```bash
# Terminal 1 — Ryu controller
ryu-manager sdn_mininet/ryu_collector.py --observe-links

# Terminal 2 — Mininet topology with injection
sudo python3 sdn_mininet/topology.py --time 120 --inject

# Terminal 3 — verify in Mininet CLI
mininet> h1 curl --max-time 3 http://10.0.0.2/   # times out (injected)
mininet> h1 ping -c 3 10.0.0.2                   # succeeds (evasion)
mininet> sh ovs-ofctl dump-flows s1 -O OpenFlow13 # shows rogue rule
```

The injected rule carries cookie `0xDEADBEEFCAFE0001` at priority 40000 and is
visible in `ovs-ofctl dump-flows`.

---

## Tool 4 — Human-in-the-Loop security dashboard

Tool 4 is the human-centered security layer. It detects anomalous flows,
explains **why** each flow was flagged, presents the operator with a clear
recommendation, and waits for the operator to decide whether to block, monitor,
or ignore. No traffic is ever blocked automatically.

### Architecture

```
ryu_collector.py ──► live_client*.csv ──► detect.py
                                               │
                                           hitl.py
                                        (AlertQueue)
                                               │
                                       explainer.py
                              (explanation + recommendation)
                                               │
                                      dashboard/app.py
                                       (Flask :5000)
                                               │
                                   Operator browser UI
                                               │  (approve)
                                       mitigator.py
                                               │
                         Ryu REST API (:8080) ──► OFPFlowMod DROP
                                          cookie=0xFEEDFACECAFE0004
                                                 priority=30000
```

### New files (Tool 4)

| File | Purpose |
|------|---------|
| `src/hitl.py` | `Alert` dataclass, `AlertQueue`, `alerts_from_detections()` |
| `src/explainer.py` | Pattern matching, human-readable explanation + recommendation |
| `sdn_mininet/mitigator.py` | Installs and removes OpenFlow DROP rules |
| `dashboard/app.py` | Flask REST API (port 5000) |
| `dashboard/templates/index.html` | Operator alert review dashboard |
| `dashboard/static/dashboard.js` | Live polling, decision flow, keyboard shortcuts |
| `config/hitl_config.yaml` | All Tool 4 thresholds, mitigation params, demo scenarios |

### Quick start (offline — no Mininet)

```bash
# Build the model first if you have not already
make all

# Launch the dashboard
python3 cli.py dashboard --model models/global.pkl --data data/new_flows.csv
```

Open `http://localhost:5000` in a browser. Click **⚡ Scan now** to detect
anomalies and populate the alert list. Select an alert to see its full
explanation and recommendation, then choose an action.

### Live Mininet mode

```bash
# Terminal 1
ryu-manager sdn_mininet/ryu_collector.py --observe-links

# Terminal 2
sudo python3 sdn_mininet/topology.py --time 120 --attack

# Terminal 3 — dashboard reads live CSV, auto-scans every 30 s
python3 cli.py dashboard --model models/global.pkl --data data/live_client1.csv
```

### Terminal mode (no browser)

```bash
# Print alerts and prompt for each one
python3 cli.py hitl --model models/global.pkl --data data/new_flows.csv --interactive

# Auto-block all HIGH-severity alerts without prompting
python3 cli.py hitl --model models/global.pkl --data data/new_flows.csv --auto-block
```

### Demo scenarios

```bash
make demo-hitl    # DDoS from h4 (live_client2.csv)
make demo-scan    # Port scan from h6 (live_client3.csv)
make demo-inject  # FlowMod injection from h7 — shows both cookies side by side
make demo-fte     # Flow table exhaustion
make demo-baseline # Clean traffic — no alerts expected
```

The `demo-inject` scenario automatically runs `ovs-ofctl dump-flows s1` after
the operator approves mitigation, showing both rules simultaneously:

```
cookie=0xfeedfacecafe0004  priority=30000  actions=drop   ← Tool 4 defensive
cookie=0xdeadbeefcafe0001  priority=40000  actions=drop   ← Tool 3 rogue
```

### Explainable alerts

Every alert includes:

- **Severity** — HIGH / MEDIUM / LOW based on anomaly rank percentile
- **Confidence** — how anomalous this flow is relative to the batch
- **Detection pattern** — named attack type (DDoS, port scan, flow table
  exhaustion, control-plane probe) or plain-language feature description
- **Feature breakdown** — the top 3 most anomalous features with Z-scores and
  observed-vs-baseline comparison
- **Recommendation** — three labelled options (Approve/Block, Monitor, Ignore)
  with specific guidance based on severity, protocol, and destination port

### REST API (port 5000)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Dashboard web UI |
| `GET` | `/api/alerts` | All alerts |
| `GET` | `/api/alerts/pending` | Pending alerts only |
| `GET` | `/api/alerts/<id>` | Single alert |
| `POST` | `/api/decide` | Submit operator decision |
| `GET` | `/api/stats` | Queue summary counts |
| `GET` | `/api/mitigation/log` | Mitigation audit log |
| `GET` | `/api/mitigation/verify` | Run `ovs-ofctl` to verify installed rules |
| `POST` | `/api/scan` | Trigger immediate detection scan |
| `GET` | `/api/health` | Server health and uptime |

Example — approve an alert and trigger mitigation:

```bash
curl -X POST http://localhost:5000/api/decide \
  -H "Content-Type: application/json" \
  -d '{"alert_id": "a1b2c3d4", "decision": "approved"}'
```

### Keyboard shortcuts

| Key | Action |
|-----|--------|
| `j` / `↓` | Next alert |
| `k` / `↑` | Previous alert |
| `a` | Approve / block |
| `m` | Monitor |
| `i` | Ignore |
| `r` | Trigger scan |
| `Escape` | Close modal |
| `?` | Show keyboard help |

### Verify mitigation

```bash
make verify
# or
sudo ovs-ofctl dump-flows s1 -O OpenFlow13 | grep feedfacecafe0004
```

Tool 4 rules use cookie `0xFEEDFACECAFE0004` at priority 30000. They
self-expire after 5 minutes of idle traffic (`idle_timeout=300`). To remove a
rule manually:

```bash
curl -X POST http://localhost:5000/api/mitigation/unblock \
  -H "Content-Type: application/json" \
  -d '{"src_ip": "10.0.0.4", "dst_port": 80, "protocol": "tcp", "dpid": 2}'
```

### Audit logs

| File | Contents |
|------|----------|
| `results/mitigator.log` | Every Block / Monitor / Ignore with timestamp, source IP, method, and cookie |
| `results/hitl_audit.log` | Scan events and alert generation counts |
| `results/ryu_sanitizer.log` | Tool 2 Z-score sanitizer reports |

---

## Full pipeline reference

### All tools, live Mininet

```bash
# Setup — run once
chmod +x install.sh && ./install.sh

# Terminal 1: Ryu controller (Tools 1, 2, 4)
ryu-manager sdn_mininet/ryu_collector.py --observe-links

# Terminal 2: Mininet topology (all attacks)
sudo python3 sdn_mininet/topology.py --time 120 --attack --inject

# Terminal 3: HITL dashboard (Tool 4)
python3 cli.py dashboard --model models/global.pkl --data data/live_client1.csv

# Terminal 4: watch flow collection
watch -n 5 wc -l data/live_client*.csv
```

### Offline pipeline (no VM)

```bash
make all          # data → train → aggregate → detect → evaluate
make hitl         # Tool 4 terminal scan
make dashboard    # Tool 4 browser dashboard
```

---

## Makefile targets

### Tools 1–2

| Target | Description |
|--------|-------------|
| `make install` | Install all Python dependencies |
| `make data` | Generate synthetic flow data |
| `make train` | Train local models (client1, 2, 3) |
| `make aggregate` | Federate local models |
| `make detect` | Score new flows |
| `make evaluate` | Evaluate on labeled test data |
| `make simulate-fl` | Multi-round FL simulation |
| `make all` | Full offline pipeline |
| `make clean` | Remove models, results, data |

### Tool 4

| Target | Description |
|--------|-------------|
| `make hitl` | One scan, print alerts to terminal |
| `make hitl-interactive` | One scan, prompt for each alert |
| `make dashboard` | Launch browser dashboard |
| `make dashboard-live` | Dashboard scanning live CSV |
| `make demo-hitl` | DDoS demo scenario |
| `make demo-scan` | Port scan demo scenario |
| `make demo-inject` | FlowMod injection demo (shows both cookies) |
| `make demo-fte` | Flow table exhaustion demo |
| `make demo-baseline` | Baseline: no alerts expected |
| `make verify` | Show Tool 4 rules on s1 via ovs-ofctl |
| `make clean-all` | Full clean including `__pycache__` |

---

## Configuration

### `config/fed_config.yaml` (Tools 1–2)

| Key | Default | Description |
|-----|---------|-------------|
| `n_rounds` | 3 | FL simulation rounds |
| `n_estimators` | 100 | Isolation Forest trees per client |
| `sanitize` | `true` | Enable Z-score sanitizer |
| `z_threshold` | 2.0 | Z-score cutoff for poisoning detection |
| `poisoned_clients` | `h6: 100.0` | Simulated poisoning in FL simulation |

### `config/hitl_config.yaml` (Tool 4)

| Key | Default | Description |
|-----|---------|-------------|
| `detection.min_confidence` | 50.0 | Minimum confidence % for alerts |
| `detection.max_alerts_per_scan` | 20 | Alert cap per scan batch |
| `auto_scan.interval_seconds` | 30 | Background scan interval |
| `mitigation.priority` | 30000 | DROP rule OpenFlow priority |
| `mitigation.idle_timeout_seconds` | 300 | Rule auto-expires after 5 min idle |
| `mitigation.cookie` | `0xFEEDFACECAFE0004` | Identifies Tool 4 rules |

---

## Running tests

```bash
# Tool 2 unit tests
python3 -m pytest tests/test_sanitizer.py -v

# Expected output: 15+ passing tests covering healthy data,
# poisoned hosts, edge cases, vector sanitizer, and Z-threshold sensitivity
```

---

## Limitations and known issues

**Mininet requires native Ubuntu.** The live traffic collection mode does not
work inside Docker because Mininet relies on Linux kernel namespaces. Use
the offline (`make all`) mode for Docker.

**L2 collector vs L3 detection.** `ryu_collector.py` records flows at the
Ethernet (MAC) layer because the learning switch does not install IP-level
match rules. The `src_ip` and `dst_ip` fields in the live CSVs contain MAC
addresses, not IP addresses. This affects which features the Isolation Forest
uses for live data versus synthetic data. The pattern matchers in
`explainer.py` are designed around the synthetic dataset's feature
distributions and may produce less specific labels on live traffic.

**Tool 4 mitigation path A requires `ofctl_rest`.** `mitigator.py` prefers the
Ryu REST API (`POST /stats/flowentry/add`) for installing DROP rules. This
requires loading the `ryu.app.ofctl_rest` app alongside `ryu_collector.py`.
If it is not loaded, the mitigator falls back to the raw OpenFlow socket path
(ptcp:6654), which works without any additional Ryu configuration.

```bash
# Load both apps together:
ryu-manager sdn_mininet/ryu_collector.py ryu.app.ofctl_rest --observe-links
```

**Demo scenarios require live CSVs.** The `make demo-hitl`, `make demo-scan`,
and `make demo-inject` targets read from `data/live_client*.csv`, which only
exist after running the Mininet topology. For a fully offline demo, point the
scenario to the synthetic data files by editing `config/hitl_config.yaml`.

**Z-threshold tuning.** The default Z-score threshold of 1.5 is calibrated for
small groups (≤9 clients). With only three clients in this lab, the sanitizer
is aggressive — a single outlier will be caught but borderline anomalies may
also be rejected. Lower the threshold in `config/fed_config.yaml` for more
permissive behavior.
