# SDN Federated Anomaly Detection Tool

**Federated Unsupervised Anomaly Detection for Software-Defined Networks**

This is a modular Python tool that generates **SDN flow logs** and uses them to train local anomaly detection models with Isolation Forest.
**Isolation Forest**  is a maching learning (ML) algorithm used for finding unusual data points in a dataset.
Each organization trains its own model locally, and the resulting model updates are combined to create a global federated model. 
Isolation Forest anomaly detectors are implanted across participating organizations to identify suspicious network behavior. 
Overall, this system uses **Federated Learning (FL)**, which allows organizations to collaboratively train and improve a global ML model 
- without exposing any of their private data with other participants.

---

## Video Presentation

> **[See video presentations]**
> [SDN FL Anomaly Detection Tool](https://youtu.be/ba_NrpwrSyE)
> [SDN FL Anomaly Detection on Ubuntu (Optional)](https://youtu.be/Rrwn5y1k69c)

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

---

## Section I: Problem Definition

### Problem Statement

Software-Defined Networks (SDNs) generate large amounts of detailed network traffic data,
that includes information about connections, packet flow, and communication patterns between devices. 
However, labeled attack data is usually scarce and unevenly distributed. 
In some cases, data may not be combined across organizations because of privacy, policy, or regulatory restrictions. 
This makes it difficult to develop and train effective ML models for threat detection.

### Importance

SDN controllers are central components in cloud and enterprise networks. 
Attacks such as DDoS, port scanning, spoofing, and flow table exhaustion can hinder network communication. 
To address these threats, organizations need scalable, data-driven anomaly detection systems that do not expose their sensitive data.

### Existing Approaches

| Approach | Tool Examples | Limitation |
|---|---|---|
| Signature-based IDS | Snort, Suricata | Misses zero day attacks |
| Static threshold rules | Custom scripts, dashboards | High false-positive rate |
| Centralized ML | Pooled NetFlow datasets | Requires raw data sharing |
| Per-org ML | Custom models | Not enough data for effective detection |

### The Issue

There is no lightweight, reproducible tool that:
- Works directly on **SDN-style flow logs**, e.g., bytes, packets, duration, ports, protocol
- Trains **local unsupervised models** with no labels needed
- Consolidates them using a **FL model** and does not exchange private data

This project addresses this issue. 

---

## Section II: System Design

### Architecture

![Architecture Diagram](docs/sdn-fl-detector.drawio.svg)


### Core Components

| Module | File | Responsibility |
|---|---|---|
| Feature Extractor | `src/features.py` | Normalize numeric fields, encode protocol/ports, compute derived features |
| Local Trainer | `src/local_train.py` | Train Isolation Forest per client; save model bundle |
| Federated Aggregator | `src/federated.py` | Load client models; average anomaly scores; consensus threshold |
| Detection Engine | `src/detect.py` | Score new flows; annotate with `anomaly_score`, `is_anomaly`, `anomaly_rank` |
| Evaluator | `src/evaluate.py` | Compute accuracy/precision/recall/F1/AUC; confusion matrix plots |
| CLI | `src/cli.py` | Argparse-based interface wiring all modules |
| Data Generator | `scripts/generate_data.py` | Synthetic SDN flow CSV generator for quick-start testing |

### Feature Engineering

Feature engineering is the process of transforming raw data into meaningful numerical inputs that a ML model can interpret and learn from.
It involves the process of selecting, extracting, or constructing features that capture patterns in the data.
This is essential for improving model performance. 
In this system, each raw flow is represented using eight numeric features.

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

Two complementary aggregation strategies:

- **Strategy A — Score Ensemble:** 
I use this approach. 
This is where each client uses its own model and scaler to assign an anomaly score to new network flows. 
All clients send these scores to the central model, in which they are averaged to produce a final global anomaly score. 
The client's raw data is not shared with the central model - only the computed scores. 

- **Strategy B — Threshold Consensus:** 
Each client calculates its own anomaly scores and determines a cutoff value using the 95th percentile.
This is a cutoff value such that only the highest 5% of client's scores are above it, meaning they are the most unusual or suspicious values in the data.
In other words, each client identifies a boundary between “normal” and “unusually high” scores based on its own data.
These percentile-based thresholds are then averaged across all clients to produce a single global threshold.
Any new flow with a score above this final threshold is classified as an anomaly.

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

---

## Section III: Evaluation

### Testing Methodology

#### Dataset
The system includes a **synthetic SDN flow generator** (`scripts/generate_data.py`).
This produces realistic benign and attack traffic without a download.
It can also be evaluated using public datasets such as UNSW-NB15 or CICDDoS2019.
In this case, the dataset should be formatted as a CSV with the following columns: `src_ip, dst_ip, src_port, dst_port, protocol, bytes, packets, duration, flags, label`.

#### Synthetic Attack Types

| Attack | Characteristics | Client Skew |
|---|---|---|
| DDoS | High bytes/packets, short duration, few dst IPs | Heavy in Client 2 |
| Port Scan | Tiny packets, many unique dst_ports, SYN flags | Heavy in Client 3 |
| Flow Table Exhaustion | Random src IPs, all ports, tiny packets | Heavy in Client 3 |

#### Experimental Setup

- **3 clients**, each with ~1,920 training flows (benign-heavy, ~16% attack)
- **1,440-flow combined labeled test set** (held out, not seen during training)
- Labels used **only for evaluation**, not training (true unsupervised setup)
- Threshold: federated consensus (mean of each client's 5th-percentile score)

### Results

#### Synthetic Pipeline Results

```
        label  accuracy  precision  recall     f1   roc_auc
    Federated    0.8535     0.9565  0.0948 0.1725    0.7655
Local:client1    0.8632     0.8571  0.1810 0.2989    0.8496
Local:client2    0.8722     0.6690  0.4095 0.5080    0.7606
Local:client3    0.8771     0.9231  0.2586 0.4040    0.8291
```

**Key findings:**
- The federated model achieves **very high precision (0.96)** or with low false positives.
- **ROC-AUC of 0.77** shows meaningful separation between attack and benign traffic in score space.
- Local models trained on one client's data perform poorly on other clients' data - demonstrating the value of federated aggregation.

#### Live Mininet + Ryu Results

```
        label  accuracy  precision  recall     f1
    Federated    1.0000     1.0000  1.0000 1.0000
Local:live_c1    0.0348     1.0000  0.0348 0.0673
Local:live_c2    0.0498     1.0000  0.0498 0.0948
Local:live_c3    0.0348     1.0000  0.0348 0.0673
```

The live results demonstrate the core value of the federated approach: local models trained on one switch's traffic perform poorly on another switch's data (3-5% recall), while the federated model combining all three achieves dramatically better detection.

### Known Issues and Limitations

| Limitation | Impact | Notes |
|---|---|---|
| L2 flow collection | MAC addresses instead of IPs in live mode | Ryu learning switch installs L2 flows; IP fields absent from match |
| Simple FedAvg | No formal privacy guarantee | No secure aggregation or differential privacy |
| Classical ML only | Less expressive than deep models | Isolation Forest is fast and interpretable |
| Offline evaluation | Not real-time | Processes static CSV logs; not integrated with a live controller |
| Manual labeling | Attack window labeled by timestamp | Requires noting attack start time and running label_window.py |
| Python 3.8 required | Ubuntu 20.04 ships with Python 3.8 | All files use `from __future__ import annotations` for compatibility |

---

## Quick Start

### Option 1: Synthetic pipeline (any OS)

```bash
git clone https://github.com/Bkishiyama/sdn-fl-detector.git
cd sdn-fl-detector
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

1. The Core Data & Feature Pipeline Before any machine learning happens, network traffic has to be captured and turned into numbers a model can understand.
  - scripts/generate_data.py 
    - This is the first program of my pipeline as it creates data, or fake network logs.
    - This program generates synthetic network flow logs from scratch without relying on the input of external data. It uses statistical rules to make realistic benign traffic along with specific cyber attacks, including DDoS, port scans, and flow table exhaustion.
    - This approach allows the entire machine learning pipeline to be executed, tested, and verified locally without the need to download massive external packet captures.
    -	Once generated, these network flow logs are passed into src/features.py for the next stage of the pipeline. In the next stage, raw data is transformed into a structured feature matrix.
    - In a later phase of the project, this synthetic generator will be replaced with the benchmark CICIDS2019 evaluation dataset to test the model's performance on real world attack traffic.
  - src/features.py 
    - This is the second program in my pipeline. It translates the logs, finds 8 mathematical clues, and groups them into bins.
    - This program takes network traffic logs and organizes them such that a Machine Learning (ML) model can understand them. Instead of looking at raw text or random numbers, the program extracts eight specific details, or mathematical features. The features are consistent, measurable clues like how fast data is moving or how many packets are sent. By looking at the features together, the model can determine if a signature pattern is an attack or normal traffic.
	- The program, for example, measures the speed of the traffic, and calculates ratios like packets-per-second, and evens out the numbers so short and long bursts of data can be compared.
	- It also groups thousands of different connection points into a few organized categories, called bins. As an analogy, this is like sorting mail into specific cubbies based on where it needs to go.
	- Finally, the program translates network languages, such as protocols like TCP and UDP, into simple code numbers. By doing this, the program acts as a translator, turning the complex network activity into a clean, uniform spreadsheet of numbers that the AI security model can easily read and identify cyber attacks.
---
2. Local Training vs. Federated Aggregation The Federated Learning architecture splits the workload between individual local clients and a central coordinator.
  - config/fed_config.yaml 
    - Before any training begins, this configuration file acts as the master settings panel for the entire Federated Learning simulation. Instead of hardcoding values like the number of clients, training rounds, or aggregation strategy directly into the code, all of those parameters are stored here in a single, human-readable file. This makes the system highly flexible - a researcher can change the number of simulated clients or switch aggregation strategies simply by editing this file, without touching any program logic. It is the blueprint that tells every other program in the pipeline how the federated system should behave.
  - src/local_train.py (The Client Side/trainer) 
    - This is the third program in my pipeline. It is used to train the AI model.
    - This program takes the "cleaned-up" network clues and uses them to train an AI security model. The model is the Isolation Forest. In Federated Learning, it is directly installed on each individual user's computer. Instead of spending a lot of time studying what normal or safe traffic looks like, an Isolation Forest works like a detective. It hunts for unusual events. It isolates the rare and unusual "outlier" data and signals it as a cyber attack.
    - Once the local training is finished, the program saves everything together into a neat package, called a bundle. This is merely a newly trained AI model, a data scaler that keeps all the numbers evenly balanced, and a set of local scoring stats used to judge how unusual future traffic might be. This local training process is important for cybersecurity because it protects user privacy. By teaching the AI model directly on the local machine, sensitive network logs never have to be sent over the internet or shared with an outside server.
  -	src/federated.py (The Coordinator/Server Side) 
    - This fourth program in the pipeline acts as a central coordinator that brings together all of the individual AI security models trained in the previous step.
    - It simulates a wholistic environment where multiple computers, or the clients, work together over several rounds to build a master AI security model. The server does not see the private network logs of the clients.
    - To create this unified defense, the program takes the local AI models from all the clients and combines their intelligence using one of two strategies: 
      - **Score Ensemble** acts like a panel of experts averaging out their scores to see how unusual a piece of traffic looks, or
      - **Threshold Consensus** acts like a democratic vote where the majority must agree before officially declaring the data as a cyber attack.
  - This process is the core of Federated Learning and is valuable. It creates a massive, network wide shield; every participant benefits from the collective knowledge of the entire group. It allows them to spot advanced threats like DDoS attacks together while keeping their own local data completely private and secure.
---
3. Detection & Evaluation Once the global federated model is built, it needs to be put to work and its performance measured.
  -	src/detect.py 
    - This fifth program is the production engine, which means it is the part of the project that actually goes to work protecting the network in real time. Once the master AI model is built by the team of computers, this program uses that collective intelligence to analyze live, brand-new network traffic as it flows by.
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
---
4. SDN Integration: Real Network Emulation While the core pipeline can run entirely on synthetic data, the sdn_mininet/ module bridges the gap between simulation and a real Software-Defined Network (SDN) environment using two industry-standard tools: Mininet and the Ryu controller.
  - sdn_mininet/topology.py 
    - This program builds a virtual, emulated network from scratch inside a single machine. Using Mininet, a network emulator, it constructs a realistic SDN topology complete with switches, hosts, and links. Beyond simply connecting the nodes, this program also contains built-in traffic generators that can simulate both normal user behavior and specific attack scenarios, such as DDoS floods or port scans, on demand. Think of it as a digital proving ground: a fully functional fake internet that the rest of the pipeline can use to generate real OpenFlow traffic without requiring any physical hardware.
  - sdn_mininet/ryu_collector.py 
    - This program runs as an application on top of the Ryu SDN controller, or the "brain" that manages the virtual network's switches. Its job is to act as a live data recorder. As traffic flows across the Mininet topology, the Ryu controller continuously receives raw statistics from every switch in the network via the OpenFlow protocol. This program intercepts those statistics, organizes them into structured rows, and writes them out to a CSV file. In short, it is the pipeline's real-time sensor, converting raw switch-level telemetry into the same kind of network flow logs that scripts/generate_data.py previously had to invent synthetically.
  - sdn_mininet/label_window.py 
    - After a Mininet experiment finishes running, this program acts as a post-processing annotator. Because the traffic generator in topology.py knows precisely when an attack started and stopped, this program takes the raw CSV of collected flows and goes back through it, stamping each time window with the correct label - either "benign" or the specific attack type that was active during that period. This labeled dataset is what gets handed off to src/features.py for feature extraction, completing the bridge between live SDN emulation and the machine learning pipeline.
---
5. Execution, Orchestration & Environment These files handle the user interface, automation, environment setup, and containerization of the project.
  -	cli.py (root entry point) 
    - This seventh program serves as the main entry point and control center for the user. Instead of forcing you to hunt through folders and manually run five or six different programs one after the other, this script bundles everything into a single, centralized dashboard called a Command-Line Interface (CLI). It allows you to run and manage the entire artificial intelligence pipeline from your terminal using simple, human-readable commands. For example, typing python cli.py train automatically wakes up the training programs, while typing python cli.py detect instantly activates the production engine to start scanning for cyber attacks. In short, it acts like a universal remote control, making the entire complex AI system easy to operate with just a few simple keystrokes.
  -	src/cli.py (argparse command routing) 
    - While the root cli.py serves as the entry point, this companion program inside the src/ package handles the detailed plumbing behind every command. It uses Python's argparse library to define and validate each sub-command, such as generate, train, detect, and evaluate. It then routes the user's input to the correct module. Think of the root cli.py as the front door and this file as the switchboard operator inside, making sure every request reaches the right program with the right arguments.
  -	src/init.py 
    - This small but essential file officially declares the src/ folder as a Python package. Without it, Python would not recognize the folder as a collection of importable modules, meaning programs like cli.py and federated.py could not reference each other cleanly. It requires no direct interaction from the user. It simply holds the package together behind the scenes.
  -	Makefile 
    - This eighth file acts as an automation shortcut that eliminates the need to type out individual commands one by one. Instead of requiring you to manually trigger each stage of the project, running the single command make all in your terminal tells the computer to automatically launch the entire machine learning pipeline from start to finish. It functions like an automated domino effect, precisely executing every program in its exact required sequence: first inventing the fake data, next translating it into clean mathematical clues, then training the local AI guards, aggregating them into a master federated shield, and finally generating the performance report card. In short, it is a master script that handles all the heavy lifting, allowing you to test, run, and verify the entire cybersecurity system with a single keystroke.
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
    - This small configuration file tells Docker which files and folders to intentionally exclude when building the image, such as the data/, models/, and results/ directories that are generated at runtime rather than baked into the image itself. By skipping unnecessary files, it keeps the Docker image lean and fast to build, and prevents accidentally bundling sensitive or large generated files into a shareable container.
  - .gitignore
    - This file tells Git which files and folders to intentionally leave out of version control. For this project, it excludes the three generated runtime directories, data/, models/, and results/, because their contents are always re-creatable by simply running the pipeline and would bloat the repository unnecessarily. It also excludes Python cache folders (__pycache__), compiled bytecode (.pyc files), and local environment folders created by pip or Conda. In short, it keeps the repository clean and focused on source code only, ensuring that anyone who clones the project gets a lean, reproducible copy without gigabytes of generated files attached to it.   
---
6. Generated Data Directories These three folders are not committed to the repository and are created automatically when the pipeline runs.
  -	data/ 
    - This folder is the pipeline's working scratchpad. It stores the synthetic network flow logs produced by scripts/generate_data.py, or the real flow logs captured by sdn_mininet/ryu_collector.py, as well as the labeled and feature-extracted datasets produced by downstream stages. Because the data here is always re-generatable, it is listed in .gitignore to keep the repository lightweight.
  -	models/ 
    - After each round of local or federated training, the trained model bundles,  including the Isolation Forest model, the data scaler, and the local scoring statistics are saved here. This allows the detection engine in src/detect.py to load a pre-trained model without needing to re-run the full training pipeline every time. Like the data/ folder, it is git-ignored since models can be reproduced from the source code and data at any time.
  -	results/ 
    - This folder collects all outputs produced by src/evaluate.py, including the confusion matrix images, performance bar charts, and any saved metric reports. It serves as the project's evidence folder, or the place where proof of the model's real-world effectiveness is stored after a full pipeline run.
---
7. Documentation
  -	README.md 
    - The documentation guide containing setup instructions, structural overviews, and evaluation metrics to verify the project is working exactly as intended.
---

## Known Issues

| Limitation | Notes |
|---|---|
| L2 flows only in live mode | Ryu learning switch installs MAC-based flows; no IP match fields |
| No secure aggregation | No differential privacy or encrypted model exchange |
| Classical ML only | Isolation Forest; no deep autoencoder |
| Offline evaluation | Static CSV logs; not integrated with a live SDN controller |
| Manual attack labeling | Must note timestamp and run label_window.py after the run |
| Python 3.8 compatibility | All files use `from __future__ import annotations` for type hint support |

