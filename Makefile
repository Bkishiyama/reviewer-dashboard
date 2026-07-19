# Makefile: SDN Federated Anomaly Detection — Human-in-the-Loop Security
# Provides one-command reproducibility for all four tools.
#
# Usage:
# make install - install Python dependencies (includes Flask for Tool 4)
# make data - generate synthetic SDN flow logs
# make train - train local Isolation Forest on each client
# make aggregate - aggregate clients into a global federated model
# make detect - run anomaly detection on new flows
# make evaluate - evaluate all models against labeled test data
# make simulate-fl - run a multi-round FL simulation (Tool 2)
# make all - data -> train -> aggregate -> detect -> evaluate
# make hitl - run one HITL scan and print alerts to terminal (Tool 4)
# make dashboard - launch the HITL operator dashboard on port 5000 (Tool 4)
# make demo-hitl - run the DDoS demo scenario interactively (Tool 4)
# make demo-scan - run the port scan demo scenario interactively (Tool 4)
# make demo-inject - run the FlowMod injection demo scenario (Tool 4)
# make verify - show all Tool 4 flow rules installed on s1
# make iot-bridge - connects mininet to IoTGoat and Kali
# make iot-connect - configures flow rules and routing for IoTGoat/Kali traffic
# make clean - remove generated models, results, and data

PYTHON = python3
CLI = $(PYTHON) cli.py

# Setup

# Install all Python dependencies.
# Flask and flask-cors are new requirements for Tool 4's dashboard.
install:
	pip install -r requirements.txt

# Tool 1 / 2: Core ML pipeline 

# Generate synthetic SDN flow data for all three clients
data:
	$(CLI) generate-data --out-dir data/ --n-clients 3 --n-benign 2000 --n-attack 400

# Train local Isolation Forest models (one per client)
train: train-c1 train-c2 train-c3

train-c1:
	$(CLI) train --data data/client1.csv --out models/client1.pkl --client-id client1

train-c2:
	$(CLI) train --data data/client2.csv --out models/client2.pkl --client-id client2

train-c3:
	$(CLI) train --data data/client3.csv --out models/client3.pkl --client-id client3

# Federated aggregation of local models into one global model
aggregate:
	$(CLI) federate --models "models/client*.pkl" --out models/global.pkl

# lines 55 to 73 add to adjust for IoTGoat trainning Jul 19
# Retrain on clean LIVE traffic instead of synthetic data (fixes false
# positives like SSDP being flagged as anomalous — see live_client3.csv).
train-live-c1:
	$(CLI) train --data data/live_client1.csv --out models/live_client1.pkl --client-id live_client1

train-live-c2:
	$(CLI) train --data data/live_client2.csv --out models/live_client2.pkl --client-id live_client2

train-live-c3:
	$(CLI) train --data data/live_client3.csv --out models/live_client3.pkl --client-id live_client3

train-live: train-live-c1 train-live-c2 train-live-c3

# Delete stale live client models before federating — avoids the
# "unknown client" KeyError from old runs with different client sets.
aggregate-live:
	rm -f models/live_client*.pkl.bak
	$(CLI) federate --models "models/live_client*.pkl" --out models/live_global.pkl


# Run anomaly detection on new flows
detect:
	$(CLI) detect \
		--model models/global.pkl \
		--data  data/new_flows.csv \
		--top-n 10 \
		--out   results/detections.csv

# Evaluate all models against labeled test data
evaluate:
	$(CLI) evaluate \
		--model models/global.pkl \
		--detections results/detections.csv \
		--data data/test_labeled.csv \
		--local-models "models/client*.pkl" \
		--out results/

# Multi-round FL simulation with Byzantine-robust sanitization (Tool 2)
simulate-fl:
	$(CLI) simulate-fl --config config/fed_config.yaml

# Full offline pipeline: data -> train -> aggregate -> detect -> evaluate
all: data train aggregate detect evaluate
	@echo ""
	@echo "-----------------------------"
	@echo "[!] Full pipeline complete!"
	@echo "[!] Results -> results/"
	@echo "-----------------------------"

# Tool 4: Human-in-the-Loop

# Run one HITL detection scan and print explainable alerts to the terminal.
# Use this to verify the explanation engine works before starting the dashboard.
# Requires: models/global.pkl and data/new_flows.csv to exist (run make all first).
hitl:
	$(CLI) hitl \
		--model models/global.pkl \
		--data data/new_flows.csv \
		--min-confidence 50.0 \
		--top-n 10

# Same as hitl but prompts the operator for each alert: [a]pprove [m]onitor [i]gnore [s]kip
hitl-interactive:
	$(CLI) hitl \
		--model models/global.pkl \
		--data data/new_flows.csv \
		--min-confidence 40.0 \
		--top-n 10 \
		--interactive

# Launch the HITL operator dashboard web server.
# Opens the browser-based alert review UI on http://localhost:5000.
# Background scanner re-runs detect() every 30 seconds automatically.
# Requires: models/global.pkl to exist (run make all or make aggregate first).
# Keep this running in a dedicated terminal — Ctrl+C to stop.
dashboard:
	$(CLI) dashboard \
		--model models/global.pkl \
		--data data/new_flows.csv \
		--port 5000

# Dashboard in live Mininet mode — scans the live collector CSV instead of
# the static test file. Run this while ryu_collector.py is collecting flows.
dashboard-live:
	$(CLI) dashboard \
		--model models/global.pkl \
		--data data/live_client1.csv \
		--port 5000

# Dashboard for the IoTGoat/Kali live attack extension. This watches s3's CSV,
# which is where the IoTGoat bridge (make iot-bridge) lands traffic.
dashboard-live-iot:
	$(CLI) dashboard \
		--model models/global.pkl \
		--data data/live_client3.csv \
		--port 5000

# Demo scenarios (for the video presentation) 

# Demo scenario A: DDoS detection and mitigation
# Uses data/live_client2.csv (h4 DDoS traffic on s2).
# Interactive: operator chooses Block/Monitor/Ignore for each alert.
demo-hitl:
	$(CLI) demo-hitl --scenario ddos --config config/hitl_config.yaml

# Demo scenario B: Port scan detection
# Uses data/live_client3.csv (h6 nmap scan on s3).
demo-scan:
	$(CLI) demo-hitl --scenario port_scan --config config/hitl_config.yaml

# Demo scenario C: FlowMod injection (Tool 3 attack detected by Tool 4)
# Uses data/live_client1.csv (h7 injector traffic on s1).
# After the operator approves, automatically verifies the installed rules with
# ovs-ofctl - showing both the Tool 3 rogue cookie and the Tool 4 defensive
# cookie side by side in the terminal.
demo-inject:
	$(CLI) demo-hitl --scenario flowmod_inject --config config/hitl_config.yaml

# Demo scenario D: Flow table exhaustion
demo-fte:
	$(CLI) demo-hitl --scenario fte --config config/hitl_config.yaml

# Demo scenario E: Baseline (no alerts expected — shows the system stays quiet)
demo-baseline:
	$(CLI) demo-hitl --scenario baseline --config config/hitl_config.yaml

# Rule verification

# Show all Tool 4 DROP rules currently installed on s1.
# Filters ovs-ofctl dump-flows output for the HITL cookie.
# Run this after approving an alert to prove the flow rule was installed.
# Requires: Mininet topology to be running with s1 active.
verify:
	@echo "[Tool 4] Checking installed flow rules on s1"
	@echo ""
	sudo ovs-ofctl dump-flows s1 -O OpenFlow13 | grep -E \
		"(feedfacecafe0004|deadbeefcafe0001|NXST_FLOW|cookie)" || \
		echo "(no flows matched — is Mininet running?)"
	@echo ""
	@echo "Cookie reference:"
	@echo "[*] Tool 4 defensive: 0xfeedfacecafe0004  priority=30000"
	@echo "[*]  Tool 3 rogue: 0xdeadbeefcafe0001  priority=40000"

# Cleanup
# Remove all generated files.
# Preserves source code, configs, and the data/ directory structure.
clean:
	rm -rf models/*.pkl results/ data/*.csv
	@echo "[!] Cleaned models, results, and generated data."

# Remove everything including the dashboard static cache (if any)
clean-all: clean
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	@echo "[!] Full clean complete."

.PHONY: install \
        data train train-c1 train-c2 train-c3 aggregate detect evaluate simulate-fl all \
        hitl hitl-interactive \
        dashboard dashboard-live dashboard-live-iot \
        demo-hitl demo-scan demo-inject demo-fte demo-baseline \
        verify \
        iot-bridge iot-connect iot-bridge-clean \
        capture-clean train-live train-live-c1 train-live-c2 train-live-c3 aggregate-live \
        clean clean-all

iot-bridge:
	@echo "Bridging IoTGoat into Mininet topology..."
	@if ! sudo ovs-vsctl br-exists s3 2>/dev/null; then \
		echo "[!] s3 not found — start 'sudo python3 sdn_mininet/topology.py' first."; \
		exit 1; \
	fi
	sudo bash sdn_mininet/setup_iot_bridge.sh

# Run this after 'make iot-bridge' to configure br-iot and s3 flow rules
# so Kali/IoTGoat traffic crosses the patch port into Mininet.
# br-iot is an OVS bridge (not a Linux bridge) so ovs-vsctl is used throughout.
# The flow rules bypass OVS loop-prevention and rewrite destination MACs
# on return traffic since IoTGoat routes replies via Ubuntu (192.168.100.211)
# rather than directly to Mininet hosts.
iot-connect:
	@echo "[!] Configuring br-iot flow rules to allow Mininet traffic..."
	sudo ovs-ofctl del-flows br-iot -O OpenFlow13
	sudo ovs-ofctl add-flow br-iot -O OpenFlow13 \
		"priority=200,arp,arp_tpa=192.168.100.211,actions=LOCAL"
	sudo ovs-ofctl add-flow br-iot -O OpenFlow13 \
		"priority=150,in_port=LOCAL,actions=output:enp0s3,output:patch-to-s3"
	sudo ovs-ofctl add-flow br-iot -O OpenFlow13 \
		"priority=100,in_port=patch-to-s3,actions=output:enp0s3,output:LOCAL"
	sudo ovs-ofctl add-flow br-iot -O OpenFlow13 \
		"priority=100,in_port=enp0s3,actions=output:patch-to-s3,output:LOCAL"
	sudo ovs-ofctl del-flows s3 -O OpenFlow13
	sudo ovs-ofctl add-flow s3 -O OpenFlow13 \
		"priority=200,arp,actions=flood"
	sudo ovs-ofctl add-flow s3 -O OpenFlow13 \
		"priority=200,icmp,actions=flood"
	sudo ovs-ofctl add-flow s3 -O OpenFlow13 \
		"priority=300,ip,in_port=4,nw_dst=10.0.0.5,actions=mod_dl_dst:00:00:00:00:03:01,output:s3-eth2"
	sudo ovs-ofctl add-flow s3 -O OpenFlow13 \
		"priority=300,ip,in_port=4,nw_dst=10.0.0.6,actions=mod_dl_dst:00:00:00:00:03:02,output:s3-eth3"
	sudo ovs-ofctl add-flow s3 -O OpenFlow13 \
		"priority=200,ip,dl_src=00:00:00:00:03:01,nw_dst=192.168.100.0/24,actions=output:patch-to-iot"
	sudo ovs-ofctl add-flow s3 -O OpenFlow13 \
		"priority=200,ip,dl_src=00:00:00:00:03:02,nw_dst=192.168.100.0/24,actions=output:patch-to-iot"
	sudo ovs-ofctl add-flow br-iot -O OpenFlow13 \
		"priority=200,ip,in_port=LOCAL,nw_dst=10.0.0.0/8,actions=output:patch-to-s3"
	sudo ovs-ofctl add-flow br-iot -O OpenFlow13 \
		"priority=200,ip,in_port=enp0s3,nw_dst=10.0.0.0/8,actions=output:patch-to-s3"
	sudo ovs-ofctl add-flow s3 -O OpenFlow13 \
		"priority=1,actions=output:patch-to-iot,NORMAL"
	sudo ovs-ofctl add-flow s3 -O OpenFlow13 \
		"priority=50,ip,nw_src=192.168.100.0/24,actions=CONTROLLER:65535,output:s3-eth2,output:s3-eth3"
	sudo ovs-ofctl add-flow s3 -O OpenFlow13 \
		"priority=50,ip,nw_dst=192.168.100.0/24,actions=CONTROLLER:65535,output:patch-to-iot"
	sudo sysctl -w net.ipv4.ip_forward=1
	@echo "[!] IoTGoat bridge connected."
	@echo "[!] On IoTGoat run: ip route del default && ip route add default via 192.168.100.211"
	@echo "[!] On Kali run: sudo ip route add 10.0.0.0/8 via 192.168.100.211"
	@echo "[!] Then verify: mininet> h5 ping -c 3 192.168.100.2"

# Capture a clean (attack-free) live traffic baseline for retraining. July 19 fix-----------
# Runs topology.py WITHOUT --attack or --inject so no malicious traffic
# contaminates the baseline. Use --external if you want IoTGoat/Kali
# SSDP/background traffic included (run 'make iot-bridge' and
# 'make iot-connect' first in that case).
# Watch data/live_client*.csv grow, then Ctrl+D out of the Mininet CLI
# to stop the capture cleanly. Drop --external if you just want the plain Mininet benign traffic without IoTGoat in the mix.
capture-clean:
	@echo "[!] Capturing clean baseline traffic (no attacks) — exit Mininet CLI (Ctrl+D) to stop"
	sudo $(PYTHON) sdn_mininet/topology.py --external --time 300

iot-bridge-clean:
	@echo "[!] Removing IoTGoat bridge"
	-sudo ovs-vsctl destroy Mirror iot-mirror
	-sudo ovs-vsctl del-port s3 patch-to-iot
	-sudo ovs-vsctl del-br br-iot
	@echo "[!] IoTGoat bridge removed."
