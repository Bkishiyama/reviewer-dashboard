I'll use DeepWiki to gather information about the reviewer-dashboard architecture.

The repository `Bkishiyama/reviewer-dashboard` is not indexed in DeepWiki. I can analyze the codebase directly to summarize the architecture instead.

The repository is not indexed in DeepWiki. I'll analyze the codebase directly to summarize the architecture.

The repository is not indexed in DeepWiki. Based on codebase analysis, here's the architecture summary:

# Architecture Summary: SDN Federated Anomaly Detection

## Overview
A four-tool security system for Software-Defined Networks combining federated ML, poisoning defense, control-plane attack simulation, and human-centered threat response.

## Core Components

### Tool 1: Federated Anomaly Detection
- **[src/local_train.py](cci:7://file:///c:/Users/Brian/reviewer-dashboard/src/local_train.py:0:0-0:0)** - Trains Isolation Forest models per switch client
- **[src/federated.py](cci:7://file:///c:/Users/Brian/reviewer-dashboard/src/federated.py:0:0-0:0)** - Federates local models into global anomaly detector
- **[src/detect.py](cci:7://file:///c:/Users/Brian/reviewer-dashboard/src/detect.py:0:0-0:0)** - Anomaly scoring engine
- **[src/features.py](cci:7://file:///c:/Users/Brian/reviewer-dashboard/src/features.py:0:0-0:0)** - Flow feature extraction and preprocessing
- **[src/evaluate.py](cci:7://file:///c:/Users/Brian/reviewer-dashboard/src/evaluate.py:0:0-0:0)** - Metrics and confusion matrix evaluation

### Tool 2: Byzantine-Robust Poisoning Defense
- **[src/sanitizer.py](cci:7://file:///c:/Users/Brian/reviewer-dashboard/src/sanitizer.py:0:0-0:0)** - Z-score sanitization for model poisoning defense
- **[sdn_mininet/poisoned_host.py](cci:7://file:///c:/Users/Brian/reviewer-dashboard/sdn_mininet/poisoned_host.py:0:0-0:0)** - Attack simulation (inflated metric upload)

### Tool 3: OpenFlow FlowMod Injection
- **[sdn_mininet/injector.py](cci:7://file:///c:/Users/Brian/reviewer-dashboard/sdn_mininet/injector.py:0:0-0:0)** - Raw OpenFlow FlowMod injection attack demo
- Sniffs unencrypted OpenFlow channel, injects rogue DROP rules

### Tool 4: Human-in-the-Loop Dashboard
- **[src/hitl.py](cci:7://file:///c:/Users/Brian/reviewer-dashboard/src/hitl.py:0:0-0:0)** - Alert dataclass and AlertQueue
- **[src/explainer.py](cci:7://file:///c:/Users/Brian/reviewer-dashboard/src/explainer.py:0:0-0:0)** - Human-readable alert text generation
- **[sdn_mininet/mitigator.py](cci:7://file:///c:/Users/Brian/reviewer-dashboard/sdn_mininet/mitigator.py:0:0-0:0)** - DROP rule installation/removal
- **[dashboard/app.py](cci:7://file:///c:/Users/Brian/reviewer-dashboard/dashboard/app.py:0:0-0:0)** - Flask REST API (port 5000)
- **`dashboard/templates/index.html`** - Operator web UI
- **`dashboard/static/dashboard.js`** - Live polling and decision flow

## SDN/Mininet Layer
- **[sdn_mininet/topology.py](cci:7://file:///c:/Users/Brian/reviewer-dashboard/sdn_mininet/topology.py:0:0-0:0)** - Mininet topology (3 switches, 7 hosts)
- **[sdn_mininet/ryu_collector.py](cci:7://file:///c:/Users/Brian/reviewer-dashboard/sdn_mininet/ryu_collector.py:0:0-0:0)** - Ryu controller + flow stats CSV writer
- **[sdn_mininet/label_window.py](cci:7://file:///c:/Users/Brian/reviewer-dashboard/sdn_mininet/label_window.py:0:0-0:0)** - Post-run CSV labeling by timestamp

## Entry Points
- **[cli.py](cci:7://file:///c:/Users/Brian/reviewer-dashboard/cli.py:0:0-0:0)** - Root CLI for all four tools
- **[src/cli.py](cci:7://file:///c:/Users/Brian/reviewer-dashboard/src/cli.py:0:0-0:0)** - Tool 1/2 command handlers

## Configuration
- **[config/fed_config.yaml](cci:7://file:///c:/Users/Brian/reviewer-dashboard/config/fed_config.yaml:0:0-0:0)** - FL simulation parameters (Tools 1-2)
- **[config/hitl_config.yaml](cci:7://file:///c:/Users/Brian/reviewer-dashboard/config/hitl_config.yaml:0:0-0:0)** - HITL thresholds and demo scenarios (Tool 4)

## Data Flow
1. **Training**: Generate synthetic data → Train local models → Federate into global model
2. **Detection**: Score flows against global model → Generate alerts
3. **Defense**: Sanitize client updates during aggregation (Z-score)
4. **Response**: Operator reviews alerts via dashboard → Installs defensive DROP rules

## Network Topology
```
Ryu Controller (port 6633)
    ├── s1 (dpid=1): h1, h2 (HTTP), h7 (injector)
    ├── s2 (dpid=2): h3, h4 (DDoS attacker)
    └── s3 (dpid=3): h5, h6 (port scanner / FL poisoner)
```
