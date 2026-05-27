<img src="docs/networkv3.jpg" style="width:100%; aspect-ratio: 10 / 3; object-fit: cover;">

# SDN Federated Learning Model with Poisoning Guard

**Tool 2: Model Posioning Sanitizer**

This tool extends my Tool 1 project from my sdn-fl-detector repository. Most files have not changed as I start off by copying my Tool 1 Repository here. My goal is to secure the machine learning (ML) pipeline. 

Tool 1 detected threats in my Software Defined Network (SDN), created logs, and used the logs in my Federated Learaning (FL) model.
Tool 2 defends the network against attackers who try to influence the FL model. 
This project utilizes a Byzantine statistical filter in the Ryu SDN controller to defend the FL model from being poisoned.
Basically, it applies a Z-score anomaly detection uploads from the clients and determines if the data is corrupted.

My Model Poisoning Sanitizer (sanitizer) relies on Byzantine Aggregation. This provides security to protect the FL model for poisoning attacks. In FL, a host can send bad training data to the central server. If the global ML model uses this data, the FL model becomes corrupted and produces an ineffective defense mechanism. The sanitizer will check data that the central server receives. It compares it with the group's data using the Z-score statistical technique. If the client's data does not match the group's data, the client data gets dropped before it gets fused into the FL model. If the client's data does not have abnormal data, it gets combined with the group's data. Federated Averaging (FedAvg) is used to create a new global model - one that can detect attacks for all clients. Meaning, the new global model is sent back to all clients so they can defend against zero day attacks. 

The main contribution is using the Byzantine statistical filtering method within an SDN-FL environment. It is important to defend the FL pipeline against malicious clients who participate in training the global protection model. 

---

## Video Presentation

IN PROGRESS - UPDATE and REMOVE when completed

Watch my videos:

> 🎥 [SDN FL Anomaly Detection Tool](https://youtu.be/ba_NrpwrSyE)  
> 📚 with [Docker copy-and-paste commands](https://1drv.ms/w/c/0b9ef4570f82165e/IQD-QWe9zvwpRKE1oNgw0TT4ATfUrsw-xcZuEtRkoxQL8yA?e=jBDDw0)

IN PROGRESS - UPDATE video and REMOVE when completed

---

## Table of Contents

1. Section I: Problem Definition
2. Section II: System Design
3. Section III: Evaluation
4. Quick Start
5. Installation
6. How to Run the Experiment
7. CLI Reference
8. Repository Structure
9. Known Issues

IN PROGRESS - UPDATE and REMOVE when completed

---

## Section I: Problem Definition

### Problem Statement

Software-Defined Networks (SDNs) generate large amounts of detailed network traffic data,
that includes information about connections, packet flow, and communication patterns between devices. 
However, labeled attack data is usually scarce and unevenly distributed. 
In some cases, data may not be combined across organizations because of privacy, policy, or regulatory restrictions. 
This makes it difficult to develop and train effective ML models for threat detection.

IN PROGRESS - UPDATE and REMOVE when completed

### Importance

SDN controllers are central components in cloud and enterprise networks. 
Attacks such as DDoS, port scanning, spoofing, and flow table exhaustion can hinder network communication. 
To address these threats, organizations need scalable, data-driven anomaly detection systems that do not expose their sensitive data.

IN PROGRESS - UPDATE and REMOVE when completed

### Existing Approaches

| Approach | Tool Examples | Limitation |
|---|---|---|
| Signature-based IDS | Snort, Suricata | Misses zero day attacks |
| Static threshold rules | Custom scripts, dashboards | High false-positive rate |
| Centralized ML | Pooled NetFlow datasets | Requires raw data sharing |
| Per-org ML | Custom models | Not enough data for effective detection |

IN PROGRESS - UPDATE and REMOVE when completed

### The Issue

There is no lightweight, reproducible tool that:
- Works directly on **SDN-style flow logs**, e.g., bytes, packets, duration, ports, protocol
- Trains **local unsupervised models** with no labels needed
- Consolidates them using a **FL model** and does not exchange private data

This project addresses this issue. 

IN PROGRESS - UPDATE and REMOVE when completed
---

## Section II: System Design

### Architecture for Tool 2

![Architecture Diagram](docs/sdn-poison-guard.drawio.svg)

IN PROGRESS - UPDATE and REMOVE when completed

Each host uses local Isolation Forest Training to detect anomalies. The model creates a metric and sends it to the Controller.
The local metric is used to make the global ML model for threat detection.
If a host sends corrupted data, it will make the global model ineffective. So, the metrics must be analyzed.
If data appears out of the norm, it is removed.
After the data is santized, with the use of Z-score calculations, the global model is generated to find incoming threats.

---

### Architecture for Tool 1

![Architecture Diagram](docs/sdn-fl-detector.drawio.svg)

In tool 1, data is generated by local hosts and sent to the central server.
IN PROGRESS - UPDATE and REMOVE when completed

---
### Core Components

![Tool 2 added](docs/tool2add.drawio.svg)

Tool 2's has added programs to Tool 1

---

#### topology.py

This is the file that builds Mininet virtual network.
Inside this file, the build() method:
- creates hosts and switches
- links the hosts ↔ switches
- links switches ↔ switches
- assigns IPs
- sets the link parameters
- prepares the network for traffic generation
  - start_benign_traffic(): Starts normal background traffic for training.
  - start_attack_traffic(): Starts malicious traffic for labeling and testing.
  - label_attack_flows(): Runs your labeling script to mark attack flows.
  - run(): Starts Mininet, launches traffic, and labels data flow. 
ryu_collector.py
This file is for collecting flow stats, and where I added REST endpoints to upload metrics - for Tool 2. The program has a SDNSanitizerController class , a data traffic manager, does:
- Negotiates traffice when a switch connects, Ryu asks: “What OpenFlow features do you support?”
- Deals with packets that the switch sends to the controller, e.g. an unknown MAC, ARP request, or packets that miss the flow table.
- Receive flow statistics reports from switches, e.g., number of bytes, packets, and match fields.
- Polls switches for updated stats.

In summary, I extended this file. I first built ryu_collector.py for Tool 1 (SDN Flow Log Collection). I expanded it to act as the REST API interface for Tool 2, my federated learning system. I added endpoints that:
- Uploads new metrics from each client to the federated model as hosts push flow feature summaries or anomaly scores
- Send client side model updates to the central server, i.e., Isolation Forest parameters.
- Starts the federated aggregation in which the server combines all client models into the Global IDS.
- Reports client status back to the controller, e.g., “model uploaded,” “aggregation complete,” “ready for next round.”

#### local_train.py

This program is used for Isolation Forest to train on incoming packet flow features.
1. Loads the local client’s flow feature CSV
2. Trains an Isolation Forest model on those features
3. Saves the trained model so it can be sent to the central controller. 

#### federated.py

This program is the used for the server FL system. It takes the Isolation Forest models trained by each client and combine them into a single Global IDS model. The file:
1. Loads client models: load_client_models() reads each client’s uploaded model bundle and prepares them for aggregation
2. Combines client anomaly scores: federated_score_ensemble() merges client predictions into a unified anomaly score for each flow
3. Determins a shared anomaly threshold: federated_threshold_consensus() computes a global threshold based on client side thresholds
4. Aggregates and saves the global model: aggregate_and_save() performs the FedAvg style aggregation and writes out the Global IDS model
5. Runs simulated FL rounds: simulate_fl_rounds() allows you test multiple rounds of federated training without running Mininet

#### sanitize.py 

This program acts as a filter that protects the FL process from malicious client updates. It evaluates each client’s update and decides whether it should be accepted, rejected, or flagged before it is injected to federated.py for aggregation. 
1. Computes stats on client updates: The mean, standard deviations, and Z scores are calculated when a client sends its vector
2. Determines poisoned updates: If the poisoning_detected function calculates that the client’s update is not within a normal range, based on a Z-score threshold, it is marked as suspicous.
3. Accepts or rejects a client update: sanitize_vector_updates stores a list, in HostReport.reason, of accepted and rejected hosts, due to “too large,” “outlier,” or “failed threshold.”
4. Stores a sanitation report that summarizes:
   - how many clients submitted
   - how many were accepted
   - how many were rejected
   - which hosts were problematic
   - the Z threshold used

#### detect.py
This program takes the Global IDS model, made by federated aggregation, and applies it to new and incoming packet flows. It has two main functions:
1. detects() function loads the global Isolation Forest model, reads a batch of flow feature rows, and computes:
   - anomaly scores
   - binary anomaly labels
   - ranked anomaly severity
   - It then writes the detection results to evaluation.py.
2. detect_local() function runs detection runs detection using a local model instead of the global one. This is used for debugging or comparing local vs. federated performance.

#### evaluate.py 

This program determines the effectiveness of my setup. It takes the outputs from detection.py and computes the standard evaluation metrics. This allows the visualization of results. It does:
1. Computes metrics: The compute_metrics() functions calculates accuracy, precision, recall, F1 score, and confusion matrix values.
2. Compares different setups: To ensure the results are worthwhile, different values are compared. For example, I compare local vs. federated and sanitized vs. unsanitized after calculating the results for each.
3. Plots the confusion matrix to show true positives, false positives, true negatives, and false negatives.
4. Creates bar charts to compare metrics across multiple setups or models.
5. Formats and prints an evaluation summary for console output and for later review.

#### Summary

In summary, the Tool 2 pipeline:
1. Mininet + Ryu collect flow stats
2. features.py extracts numerical features
3. local_train.py trains local Isolation Forests
4. federated.py aggregates them into a Global IDS
5. detect.py applies that global model to new flows
6. evaluate.py determines the effectiveness of the system.


#### Tool 1 Development

| Module | File | Responsibility |
|---|---|---|
| Feature Extractor | `src/features.py` | Normalize numeric fields, encode protocol/ports, compute derived features |
| Local Trainer | `src/local_train.py` | Train Isolation Forest per client; save model bundle |
| Federated Aggregator | `src/federated.py` | Load client models; average anomaly scores; consensus threshold |
| Detection Engine | `src/detect.py` | Score new flows; annotate with `anomaly_score`, `is_anomaly`, `anomaly_rank` |
| Evaluator | `src/evaluate.py` | Compute accuracy/precision/recall/F1/AUC; confusion matrix plots |
| CLI | `src/cli.py` | Argparse-based interface wiring all modules |
| Data Generator | `scripts/generate_data.py` | Synthetic SDN flow CSV generator for quick-start testing |

---

### Feature Engineering

Feature engineering is the process of transforming raw data into meaningful numerical inputs that a ML model can interpret and learn from.
It involves the process of selecting, extracting, or constructing features that capture patterns in the data.
This is essential for improving model performance. 
In this system, each raw flow is represented using eight numeric features.

IN PROGRESS - UPDATE and REMOVE when completed

| Feature | Description |
|---|---|
| `bytes` | Total bytes transferred (normalized) |
| `packets` | Total packet count (normalized) |
| `duration` | Flow duration in seconds (normalized) |
| `bytes_per_packet` | Derived: bytes divided by packets |
| `packet_rate` | Derived: packets divided by duration |
| `protocol_enc` | Encoded: TCP=0, UDP=1, ICMP=2, Other=3 |
| `src_port_bin` | Binned: system (0-1023)=0, registered=1, dynamic=2 |
| `dst_port_bin` | Binned: same bins as src |

### Federated Aggregation Design

I use a **Score Ensemble**  aggregation strategy.   
This is where each client uses its own model and scaler to assign an anomaly score to new network flows. 
All clients send these scores to the central model, in which they are averaged to produce a final global anomaly score. 
The client's raw data is not shared with the central model - only the computed scores. 

IN PROGRESS - UPDATE and REMOVE when completed

### Technology Choices

| Component | Choice | Justification |
|---|---|---|
| Language | Python 3.8+ | For analysis and ML |
| ML | scikit-learn IsolationForest | Lightweight |
| Data | pandas, numpy | Fast flow log processing |
| Serialization | joblib | Fast sklearn model pickling |
| CLI | argparse | No extra dependencies & easy to extend |
| Config | PyYAML | Easy to read FL simulation config |
| Graphs | matplotlib, seaborn | Standard evaluation |

IN PROGRESS - UPDATE and REMOVE when completed

---

## Section III: Evaluation

### Testing Methodology

#### Dataset
The system includes a **synthetic SDN flow generator** (`scripts/generate_data.py`).
This produces realistic benign and attack traffic without a download.
It can also be evaluated using public datasets such as UNSW-NB15 or CICDDoS2019.
In this case, the dataset should be formatted as a CSV with the following columns: `src_ip, dst_ip, src_port, dst_port, protocol, bytes, packets, duration, flags, label`.

IN PROGRESS - UPDATE and REMOVE when completed

#### Synthetic Attack Types

| Attack | Characteristics | Client Skew |
|---|---|---|
| DDoS | High bytes/packets, short duration, few dst IPs | Heavy in Client 2 |
| Port Scan | Tiny packets, many unique dst_ports, SYN flags | Heavy in Client 3 |
| Flow Table Exhaustion | Random src IPs, all ports, tiny packets | Heavy in Client 3 |

IN PROGRESS - UPDATE and REMOVE when completed

#### Experimental Setup

- **3 clients**, each with about 1,920 training flows (benign-heavy, 16% attack)
- **1,440-flow combined labeled test set** (held out, not seen during training)
- Labels used **only for evaluation**, not training (true unsupervised setup)
- Threshold: federated consensus (mean of each client's 5th-percentile score)

IN PROGRESS - UPDATE and REMOVE when completed

### Results

#### Synthetic Pipeline Results

```
        label  accuracy  precision  recall     f1   roc_auc
    Federated    0.8535     0.9565  0.0948 0.1725    0.7655
Local:client1    0.8632     0.8571  0.1810 0.2989    0.8496
Local:client2    0.8722     0.6690  0.4095 0.5080    0.7606
Local:client3    0.8771     0.9231  0.2586 0.4040    0.8291
```
IN PROGRESS - UPDATE and REMOVE when completed

**Key findings:**
- The federated model achieves **very high precision (0.96)** or with low false positives.
- **ROC-AUC of 0.77** shows meaningful separation between attack and benign traffic in score space.
- Local models trained on one client's data perform poorly on other clients' data - demonstrating the value of federated aggregation.

IN PROGRESS - UPDATE and REMOVE when completed

#### Live Mininet + Ryu Results

```
        label  accuracy  precision  recall     f1
    Federated    1.0000     1.0000  1.0000 1.0000
Local:live_c1    0.0348     1.0000  0.0348 0.0673
Local:live_c2    0.0498     1.0000  0.0498 0.0948
Local:live_c3    0.0348     1.0000  0.0348 0.0673
```

The live results demonstrate the core value of the federated approach: local models trained on one switch's traffic perform poorly on another switch's data (3-5% recall), while the federated model combining all three achieves dramatically better detection.

IN PROGRESS - UPDATE and REMOVE when completed

### Known Issues and Limitations

| Limitation | Impact | Notes |
|---|---|---|
| L2 flow collection | MAC addresses instead of IPs in live mode | Ryu learning switch installs L2 flows; IP fields absent from match |
| Simple FedAvg | No formal privacy guarantee | No secure aggregation or differential privacy |
| Classical ML only | Less expressive than deep models | Isolation Forest is fast and interpretable |
| Offline evaluation | Not real-time | Processes static CSV logs; not integrated with a live controller |
| Manual labeling | Attack window labeled by timestamp | Requires noting attack start time and running label_window.py |
| Python 3.8 required | Ubuntu 20.04 ships with Python 3.8 | All files use `from __future__ import annotations` for compatibility |

IN PROGRESS - UPDATE and REMOVE when completed

---

## Quick Start

IN PROGRESS - UPDATE and REMOVE when completed

### Option 1: Synthetic pipeline (any OS)

```bash
git clone https://github.com/Bkishiyama/sdn-poison-guard.git
cd sdn-fl-detector
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
make all
```

### Option 2: Docker (any OS, no Python needed)

```bash
git clone https://github.com/Bkishiyama/sdn-fl-detector.git
cd sdn-fl-detector
docker compose up
```

### Option 3: Live Mininet + Ryu (Ubuntu 20.04 VM only)

```bash
git clone https://github.com/Bkishiyama/sdn-fl-detector.git
cd sdn-fl-detector
chmod +x install.sh
./install.sh
```

Then follow the Live Mode steps below.

---

## Installation
IN PROGRESS - UPDATE and REMOVE when completed
### Requirements

- Python 3.8+
- Ubuntu 20.04 (for live Mininet mode only)
- Docker (for Docker mode only)

### pip

```bash
pip3 install -r requirements.txt
```

### Conda

```bash
conda env create -f environment.yml
conda activate sdn-fl-env
```

### Verify

```bash
python3 cli.py --help
```

---

## How to Run
IN PROGRESS - UPDATE and REMOVE when completed
### Method 1: Synthetic Pipeline

```bash
# Generate synthetic SDN flow data
python3 cli.py generate-data --out-dir data/ --n-clients 3 --n-benign 2000 --n-attack 400

# Train local models
python3 cli.py train-local --data data/client1.csv --out models/client1.pkl --client-id client1
python3 cli.py train-local --data data/client2.csv --out models/client2.pkl --client-id client2
python3 cli.py train-local --data data/client3.csv --out models/client3.pkl --client-id client3

# Aggregate into global federated model
python3 cli.py federated-aggregate --models "models/client*.pkl" --out models/global.pkl

# Detect anomalies
python3 cli.py detect --model models/global.pkl --data data/new_flows.csv --top-n 10 --out results/detections.csv

# Evaluate
python3 cli.py evaluate --model models/global.pkl --data data/test_labeled.csv \
                        --local-models "models/client*.pkl" --out results/
```

Or run everything in one command:

```bash
make all
```

---
### Method 2: Docker
IN PROGRESS - UPDATE and REMOVE when completed
#### Step 1: Install Docker**

Go to the website and install Docker on Windows, Linux, or MAC

Example install on Linux, Ubuntu 24.04

**1. Set up Docker apt repository**
```
# Add Docker's official GPG key:
sudo apt update
sudo apt install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
sudo tee /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF

sudo apt update
```

**2. Install the Docker packages**
```
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```


**3. Verify that the installation by viewing message**
Verify installation by running the following:
```
sudo docker run hello-world
```
>[!Note]After installation, you can verify Docker is running
```
sudo systemctl status docker
```

>[!Note]If it is not running, start it, then run hello world
```bash
sudo systemctl start docker
```

#### Step 2: Add yourself to the Docker group

```bash
sudo usermod -aG docker $USER
newgrp docker
```

#### Step 3: Clone the repo

```bash
git clone https://github.com/Bkishiyama/sdn-fl-detector.git
cd sdn-fl-detector
```

#### Step 4: Build and Run

```bash
docker compose up
```

#### Step 5: View results

Results are printed to your screen and also saved to `./results/` on your host machine.

#### Step 6: Clean up

```bash
docker compose download
```

> **Note:** Docker runs the synthetic pipeline only. Mininet live mode requires Ubuntu 20.04 natively.

---

### Method 3: Live Mode (Mininet + Ryu, Ubuntu 20.04)

#### Topology

![Controller Diagram](docs/ryu_controller.drawio.svg)

#### Step-by-Step

**Step 1: Install (one time):**
```bash
chmod +x install.sh
./install.sh
source ~/.bashrc
```

**Step 2: Terminal 1, start Ryu:**
```bash
cd ~/sdn-fl-detector
ryu-manager sdn_mininet/ryu_collector.py --observe-links
```

**Step 3: Terminal 2, start Mininet:**
```bash
cd ~/sdn-fl-detector
sudo python3 sdn_mininet/topology.py --time 120 --attack
```

**Step 4: Terminal 3, watch flows:**
```bash
watch -n 5 wc -l ~/sdn-fl-detector/data/live_client*.csv
```

**Step 5: Label attack flows**
Use timestamp printed in Terminal 2:
```bash
python3 sdn_mininet/label_window.py \
  --file data/live_client2.csv \
  --all \
  --label 1
```
  
(Optional) To narrow the time frame
```bash
python3 sdn_mininet/label_window.py \
  --file data/live_client2.csv \
  --start "YYYY-MM-DDTHH:MM:SS" \
  --end   "YYYY-MM-DDTHH:MM:SS" \
  --label 1
```

**Step 6: Train, aggregate, detect:**
```bash
python3 cli.py train-local --data data/live_client1.csv --out models/live_c1.pkl --client-id live_c1
python3 cli.py train-local --data data/live_client2.csv --out models/live_c2.pkl --client-id live_c2
python3 cli.py train-local --data data/live_client3.csv --out models/live_c3.pkl --client-id live_c3
python3 cli.py federated-aggregate --models "models/live_*.pkl" --out models/live_global.pkl
python3 cli.py detect --model models/live_global.pkl --data data/live_client2.csv --top-n 10
```

**Step 7: Evaluate:**
```bash
python3 cli.py evaluate --model models/live_global.pkl --data data/live_client2.csv \
                        --local-models "models/live_c*.pkl" --out results/live/
```

**Step 8: View results:**
```bash
nautilus results/live/
```

**Cleanup after each run:**
```bash
sudo mn -c
```

#### VirtualBox Tips

- Allocate **2 GB RAM minimum** and **2 CPU cores minimum**
- Always use `sudo python3`, not `sudo python`
- If port 6633 is busy: `sudo fuser -k 6633/tcp`
- If Mininet crashes mid-run: `sudo mn -c` before retrying

---

## CLI Reference
IN PROGRESS - UPDATE and REMOVE when completed
| Command | Description |
|---|---|
| `generate-data` | Generate synthetic SDN flow CSVs for N clients |
| `train-local` | Train a local Isolation Forest on one client's data |
| `federated-aggregate` | Aggregate client models into a global ensemble |
| `detect` | Score new SDN flows for anomalies |
| `evaluate` | Compare federated vs local models on labeled test data |
| `simulate-fl` | Run a multi-round FL simulation from a YAML config |

Run `python3 cli.py <command> --help` for full options on any command.

---

## Repository Structure

IN PROGRESS - UPDATE and REMOVE when completed

1. The Core Data & Feature Pipeline

Before any machine learning happens, network traffic has to be captured and turned into numbers a model can understand.
  - scripts/generate_data.py 
    - This is the first program of my pipeline as it creates data, or fake network logs. This program generates synthetic network flow logs from scratch without relying on the input of external data. It uses statistical rules to make realistic benign traffic along with specific cyber attacks, including DDoS, port scans, and flow table exhaustion. This approach allows the entire machine learning pipeline to be executed, tested, and verified locally without the need to download massive external packet captures. Once generated, these network flow logs are passed into src/features.py for the next stage of the pipeline. In the next stage, raw data is transformed into a structured feature matrix. In a later phase of the project, this synthetic generator will be replaced with the benchmark CICIDS2019 evaluation dataset to test the model's performance on real world attack traffic.
  - src/features.py 
    - This is the second program in my pipeline. It translates the logs, finds 8 mathematical clues, and groups them into bins. This program takes network traffic logs and organizes them such that a Machine Learning (ML) model can understand them. Instead of looking at raw text or random numbers, the program extracts eight specific details, or mathematical features. The features are consistent, measurable clues like how fast data is moving or how many packets are sent. By looking at the features together, the model can determine if a signature pattern is an attack or normal traffic. The program, for example, measures the speed of the traffic, and calculates ratios like packets-per-second, and evens out the numbers so short and long bursts of data can be compared. It also groups thousands of different connection points into a few organized categories, called bins. As an analogy, this is like sorting mail into specific cubbies based on where it needs to go. Finally, the program translates network languages, such as protocols like TCP and UDP, into simple code numbers. By doing this, the program acts as a translator, turning the complex network activity into a clean, uniform spreadsheet of numbers that the AI security model can easily read and identify cyber attacks.
---
2. Local Training vs. Federated Aggregation

The Federated Learning architecture splits the workload between individual local clients and a central coordinator.
  - config/fed_config.yaml 
    - Before any training begins, this configuration file acts as the master settings panel for the entire Federated Learning simulation. Instead of hardcoding values like the number of clients, training rounds, or aggregation strategy directly into the code, all of those parameters are stored here in a single, human-readable file. This makes the system highly flexible. A researcher can change the number of simulated clients or switch aggregation strategies simply by editing this file. It tells every other program in the pipeline how the federated system should behave.
  - src/local_train.py (The Client Side/trainer) 
    - This is the third program in my pipeline. It is used to train the AI model. This program takes the "cleaned-up" network clues and uses them to train an AI security model. The model is the Isolation Forest. In Federated Learning, it is directly installed on each individual user's computer. Instead of spending a lot of time studying what normal or safe traffic looks like, an Isolation Forest works like a detective. It hunts for unusual events. It isolates the rare and unusual "outlier" data and signals it as a cyber attack.
    - Once the local training is finished, the program saves everything together into a neat package, called a bundle. This is merely a newly trained AI model, a data scaler that keeps all the numbers evenly balanced, and a set of local scoring stats used to judge how unusual future traffic might be. This local training process is important for cybersecurity because it protects user privacy. By teaching the AI model directly on the local machine, sensitive network logs never have to be sent over the internet or shared with an outside server.
  -	src/federated.py (The Coordinator/Server Side) 
    - This fourth program in the pipeline acts as a central coordinator that brings together all of the individual AI security models trained in the previous step. It simulates a wholistic environment where multiple computers, or the clients, work together over several rounds to build a master AI security model. The server does not see the private network logs of the clients. To create this unified defense, the program takes the local AI models from all the clients and combines their intelligence using one of two strategies: 
      - **Score Ensemble** acts like a panel of experts averaging out their scores to see how unusual a piece of traffic looks, or
      - **Threshold Consensus** acts like a democratic vote where the majority must agree before officially declaring the data as a cyber attack.
  - This process is the core of Federated Learning. It creates a massive, network wide protection shield; every participant benefits from the collective knowledge of the entire group. They will be able to spot advanced threats like DDoS attacks together while keeping their own local data and completely private and secure.
---
  2.5 The Zero-Trust Security Guard
  
  This is Tool 2 that I am adding to Tool 1.  
  - src/sanitizer.py
    -  This program (Step 4.5) is next in the pipeline. Before the coordinator runs the Score Ensemble or Threshold Consensus, it inspects the client data that it receives. When it receives data from a client, the data is compared against the groups data by using a Z-score. The Z-score measures client values against the group's values and determines if there are any deviations. If there are deviations, the data is dropped and data gets logged as a security violation. This way, the data is not injected into the FL model. The FL model is forumulated without corrupted data and thus remains reliable. 
---
3. Detection & Evaluation

Once the global federated model is built, it needs to be put to work and its performance measured.
  -	src/detect.py 
    - This fifth program is the production engine, which means it is the part of the project that actually goes to work protecting the network in real time. Once the master AI model is built by the team of computers, this program uses that collective intelligence to analyze live, new network traffic as it flows by.
    - The program evaluates every connection and automatically tags the data with three specific labels: 
      - an anomaly score to measure exactly how suspicious the traffic behaves,
      - an is_anomaly trigger which acts as a yes-or-no alarm button, and
      - an anomaly rank to grade the threat's severity level from low to critical.
    - Overall, this is where the AI stops practicing on fake data and starts to diagnose whether new live traffic is benign or a malignant cyber attack.
  - src/evaluate.py 
    -	This sixth program acts as the final report card for the AI pipeline as a whole. It tests the master defense AI model to see how well it performs in the real world. To do this, it calculates standard data science metrics that grade the system's intelligence from different angles: 
      - Accuracy - overall correctness
      - Precision - how trustworthy its alarms are
      - Recall - its ability to catch every single threat
      - F1-Score - the balance between precision and recall
      - AUC - its overall grading curve
    - It also shows visual aids
      - Confusion matrices -  grid charts that show what the AI got right versus what it misdiagnosed
      - Performance bar charts. 
    - In essense, this evaluation shows whether the AI is actually effective. A high precision score means the AI won't annoy network administrators with false alarms, while a high recall score shows that the system won't completely miss a malignant attacks.
  - tests/test_sanitizer.py
    - This script is for automated verification. Before using the sanitizer in the Ryu controller, we want to test it. Verification should be completed for every condition that is used. ChatGPT provided 29 assertions that should be tested in four different scenarios:
      - A healthy network where all six hosts are honest. This should show no rejections.
      - A single poisoned host where host 6 (h6) should be detected and removed.
      - Edge cases with empty inputs, groups too small for statistical analysis, and all uploads are identical.
      - Vector sanitation for hosts that upload an array of parameters instead of a single number.
    - Usage: python3 -m pytest tests/test_sanitizer.py -v      
---
4. SDN Integration Real Network Emulation 

The core pipeline can run on synthetic data. The sdn_mininet/ module is used to bridge the gap between simulation and a real SDN environment by using Mininet and a Ryu controller.
  - sdn_mininet/topology.py 
    - This program builds a virtual, emulated network from scratch, by using Mininet, a network emulator. It constructs a realistic SDN topology with a controller, switches, and hosts. It then links these components together so they can communicate with each other. Additionally, this program contains built-in traffic generators that simulate both normal user behavior and network attacks, such as DDoS floods or port scans. This appears as a functional simulated internet with a pipeline that generates OpenFlow traffic without using any physical hardware.
  - sdn_mininet/poisoned_host.py
    - This program is an addition to Tool 1. It is added such that Tool 2 provides an attack. Host 6 runs this attack as an inside attacker. Instead of loading legitimate parameters from its locally trained model, H6 sends corrupted data, or metrics, to the Ryu controller. The simulted attack will need to be sanitized in order to defend against the attack. While this script is produces an attack, the defense is set up in src/sanitizer.py and sdn_mininet/ryu_collector.py. After the Ryu controller, or ryu_collector.py, receives the data from the hosts, the data is passed to sanitizer.py where the metrics are inspected. If it is poisoned, the metrics are dropped and not added to the FL global model. The sanitized data is then sent to federated.py where it aggregates only verified clean uploads from the honest hosts. 
  - sdn_mininet/ryu_collector.py 
    - This program runs as an application on top of the Ryu SDN controller, or the "brain" that manages the virtual network's switches. Its job is to act as a data recorder. As traffic flows across the Mininet topology, the Ryu controller continuously receives raw statistics from every switch in the network via the OpenFlow protocol. This program receives those statistics, organizes them into structured rows, and writes them to a CSV file. In short, it is the pipeline's real-time sensor, converting switch data into network flow logs. This is similar to my first phase where I had scripts/generate_data.py make data synthetically.
    - For Tool 2, I extend the functionality of Tool 1 by adding REST API endpoints. This allows the hosts, in Mininet, to send their local data to the controller. In turn, this allows the sanitizer to receive and process data. The first endpoint, POST /fl/upload, is used for clients to upload their local model metrics. The second endopoint, GET /fl/status, allows users to check the current state of the FL model and get information from it. This program also calls the sanitizer before calculating Federated Averaging (FedAvg). This ensures that the updates are filtered by using statistical analysis. Any suspicious updates from the clients are found in the ryu_sanitizer.log. This part of the novelty such that it does not blindly accept all updates. It filters out suspicious updates before updating the global model.    
  - sdn_mininet/label_window.py 
    - After a Mininet experiment finishes running, this program acts as a post-processing annotator. Because the traffic generator in topology.py knows when an attack started and stopped, this program takes the raw CSV of collected flows. It then reviews it and stamps each time window with the correct label, as either "benign" or the specific attack type that was active during that period. This labeled dataset is what gets forwarded to src/features.py for feature extraction. This finishes the bridge between live SDN emulation and machine learning pipeline.
---
5. Execution, Orchestration & Environment

These files handle the user interface, automation, environment setup, and containerization of the project.
  -	cli.py (root entry point) 
    - This seventh program serves as the main entry point and control center for the user. Instead of forcing you to look through folders and manually run five or six different programs one after the other, this script combines everything into a single, centralized dashboard called a Command-Line Interface (CLI). It allows you to run and manage the entire artificial intelligence pipeline from your terminal using simple commands. For example, typing python cli.py train automatically wakes up the training programs, while typing python cli.py detect activates the production engine to start scanning for cyber attacks. In short, it acts like a universal remote control, making the AI system easy to operate.
  -	src/cli.py (argparse command routing) 
    - While the root cli.py serves as the entry point, this program inside the src/ package handles the detailed tasks behind every command. It uses Python's argparse library to define and validate each sub-command, such as generate, train, detect, and evaluate. It then routes the user's input to the correct module. Think of the root cli.py as the front door and this file as the switchboard operator inside, making sure every request reaches the right program with the right arguments.
    - ChatGPT AI: What command lines do you recommend I include in my program where I use a SDN-FL model that is basic. I can extend my "front door" in Tool 1. In Tool 2, I can add additional commands. A demo command can run a standalone poisoning attack and defense. The sanitize command alllows a user feed a CSV client numbers through the Z-score filter and see a report of that client. The simulate-fl command now has new flags, i.e., --sanitize, --no-sanitize, and --poison h6:100. This allows the suer to toggle the defense on or off and use a poisoned client from the CLI. 
  -	src/init.py 
    - This file declares the src/ folder as a Python package. Without it, Python would not recognize the folder as a collection of importable modules. In other words, programs like cli.py and federated.py could not reference each other. It holds the package together behind the scenes.
  -	Makefile 
    - This eighth file acts as an automation shortcut. I do the commands in my video, one by one, but this allows you not to do that. The seqeuence: first invents the fake data, next translates it into clean mathematical clues, then training the local AI guards, aggregating them into a consolidated federated model, and finally evaluates the system. In short, it is a script that handles all the heavy lifting, allowing you to test, run, and verify the entire cybersecurity system without entering any commands.
  -	install.sh 
    - This shell script is a one time setup assistant designed specifically for Ubuntu 20.04 machines. When ran on a fresh system, it automatically installs all of the necessary system-level software dependencies, such as Python, Mininet, and the Ryu controller. Pip or conda cannot install these on their own. It prepares the host machine's operating system before any Python environment is created.
  -	requirements.txt 
    - This standard Python file lists every third party library the project depends on, along with their required versions. When setting up the project in a plain Python virtual environment, running pip install -r requirements.txt reads this list and automatically downloads and installs every dependency in one step. It guarantees that anyone running the project uses the exact same library versions, eliminating the "it works on my machine" problem.
  -	environment.yml 
    - This file serves the same purpose as requirements.txt but for users who prefer Conda as their package manager. Running conda env create -f environment.yml builds a fully isolated Conda environment with all the correct dependencies pre-configured. It is particularly useful for researchers and data scientists who rely on Conda to manage complex scientific computing environments.
  -	Dockerfile 
    - This file contains the instructions for packaging the entire project into a self-contained Docker image. It tells Docker exactly how to build the environment, which base operating system to use, which packages to install, and which files to copy in, so the project can run identically on any machine. 
  -	docker-compose.yml 
    - This file orchestrates multi-container deployments of the project. Rather than starting Docker containers one by one with individual commands, docker-compose.yml defines all the services the project needs, such as the training client and the federated coordinator. It then launches them together with a single docker compose up command. It also handles the networking between containers, making it straightforward to simulate multiple federated clients running simultaneously on one machine.
  -	.dockerignore 
    - This configuration file tells Docker which files and folders to exclude when building the image, such as the data/, models/, and results/ directories that are generated at runtime. By excluding these files, the Docker image remains robust.
  - .gitignore
    - This file tells Git which files and folders to leave out of version control. For this project, it excludes the three generated runtime directories, data/, models/, and results/. Theire contents are re-creatable by simply running the pipeline and would increase the repository unnecessarily. It also excludes Python cache folders (__pycache__), compiled bytecode (.pyc files), and local environment folders created by pip or Conda.  
---
6. Generated Data Directories

These three folders are not committed to the repository and are created automatically when the pipeline runs.
  -	data/ 
    - This folder is the pipeline's working scratchpad. It stores the synthetic network flow logs produced by scripts/generate_data.py, or the real flow logs captured by sdn_mininet/ryu_collector.py. It also stores the labeled and feature-extracted datasets produced by downstream stages. The data is re-generatable, so it is listed in .gitignore.
  -	models/ 
    - After each round of local or federated training, the trained model bundles,  including the Isolation Forest model, the data scaler, and the local scoring statistics are saved here. This allows the detection engine in src/detect.py to load a pre-trained model without needing to re-run the full training pipeline. Like the data/ folder, it is git-ignored since models can be reproduced.
  -	results/ 
    - This folder collects and stores all outputs produced by src/evaluate.py, which includes the confusion matrix images, performance bar charts, and any saved metric reports.
---
7. Documentation
  -	README.md 
    - The documentation guide containing setup instructions, structural overviews, and evaluation metrics to verify the project is working exactly as intended.
---

## Known Issues

IN PROGRESS - UPDATE and REMOVE when completed

| Limitation | Notes |
|---|---|
| L2 flows only in live mode | Ryu learning switch installs MAC-based flows; no IP match fields |
| No secure aggregation | No differential privacy or encrypted model exchange |
| Classical ML only | Isolation Forest; no deep autoencoder |
| Offline evaluation | Static CSV logs; not integrated with a live SDN controller |
| Manual attack labeling | Must note timestamp and run label_window.py after the run |
| Python 3.8 compatibility | All files use `from __future__ import annotations` for type hint support |

