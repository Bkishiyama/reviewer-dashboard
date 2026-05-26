# Makefile: SDN Federated Anomaly Detection Tool
# Provides one-command reproducibility.
#
# Useage:
# make install - install Python dependencies
# make data - generate synthetic SDN flow logs
# make train - train local Isolation Forest on each client
# make aggregate - aggregate clients into a global federated model
# make detect - run anomaly detection on new flows
# make evaluate - evaluate all models against labeled test data
# make simulate-fl - run a multi-round FL simulation
# make all - data -> train -> aggregate -> detect -> evaluate
# make clean - remove generated models and results

PYTHON = python
CLI    = $(PYTHON) cli.py

# Setup
install:
	pip install -r requirements.txt

# Data generation 
data:
	$(CLI) generate-data --out-dir data/ --n-clients 3 --n-benign 2000 --n-attack 400

# Local training
train: train-c1 train-c2 train-c3

# Tool 2 Note: change train-local in all to train
train-c1:
	$(CLI) train --data data/client1.csv --out models/client1.pkl --client-id client1

train-c2:
	$(CLI) train --data data/client2.csv --out models/client2.pkl --client-id client2

train-c3:
	$(CLI) train --data data/client3.csv --out models/client3.pkl --client-id client3

# Federated aggregation
aggregate:
	$(CLI) federated-aggregate --models "models/client*.pkl" --out models/global.pkl

# Detection
detect:
	$(CLI) detect \
		--model models/global.pkl \
		--data  data/new_flows.csv \
		--top-n 10 \
		--out   results/detections.csv

# Evaluation
evaluate:
	$(CLI) evaluate \
		--model        models/global.pkl \
		--data         data/test_labeled.csv \
		--local-models "models/client*.pkl" \
		--out          results/

# Multi-round FL simulation
simulate-fl:
	$(CLI) simulate-fl --config config/fed_config.yaml

# Full pipeline
all: data train aggregate detect evaluate
	@echo ""
	@echo "-----------------------------"
	@echo "[!] Full pipeline complete!"
	@echo "[!] Results -> results/"
	@echo "-----------------------------"

# Cleanup
clean:
	rm -rf models/*.pkl results/ data/

.PHONY: install data train train-c1 train-c2 train-c3 aggregate detect evaluate simulate-fl all clean
