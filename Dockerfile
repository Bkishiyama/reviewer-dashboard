# Dockerfile — SDN FL Poison Guard Tool
# Runs the full synthetic pipeline (generate -> train -> filter -> aggregate -> detect -> evaluate).
# Note: Mininet + Ryu live mode requires Ubuntu 20.04 natively (see README).
# Build:
#   docker build -t sdn-poison-guard .
# Run full pipeline:
# docker run --rm -v $(pwd)/results:/app/results sdn-poison-guard
# Interactive shell:
# docker run --rm -it -v $(pwd)/results:/app/results sdn-poison-guard bash

FROM python:3.10-slim

LABEL maintainer="Brian.Kishiyama@trojans.dsu.edu"
LABEL description="SDN FL Poison Guard Tool"

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Working directory
WORKDIR /app
COPY . /app

# Python dependencies (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/  ./src/
COPY scripts/  ./scripts/
COPY config/  ./config/
COPY sdn_mininet/ ./sdn_mininet/
COPY cli.py  .

# Create directories
RUN mkdir -p data models results

# Default command: run the full pipeline
CMD ["bash", "-c", "\
  echo '=== Generating synthetic SDN flow data ===' && \
  python cli.py generate-data --out-dir data/ --n-clients 3 --n-benign 2000 --n-attack 400 && \
  echo '' && \
  echo '=== Training local models ===' && \
  python cli.py train --data data/client1.csv --out models/client1.pkl --client-id client1 && \
  python cli.py train --data data/client2.csv --out models/client2.pkl --client-id client2 && \
  python cli.py train --data data/client3.csv --out models/client3.pkl --client-id client3 && \
  echo '' && \
  echo '=== Federated aggregation ===' && \
  python cli.py federate --models 'models/client*.pkl' --out models/global.pkl && \
  echo '' && \
  echo '=== Running detection ===' && \
  python cli.py detect --model models/global.pkl --data data/new_flows.csv --top-n 10 --out results/detections.csv && \
  echo '' && \
  echo '=== Evaluating models ===' && \
  python cli.py evaluate --model models/global.pkl --data data/test_labeled.csv \
    --detections results/detections.csv \
    --local-models 'models/client*.pkl' --out results/ && \
  echo '' && \
  echo ' +-+-+-+-+  Done! Results are in /app/results/  +-+-+-+-+'\
"]
