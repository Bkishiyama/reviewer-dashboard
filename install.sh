#!/usr/bin/env bash
# install.sh — Ubuntu 20.04 setup for SDN Federated Anomaly Detection Lab
#
# This script installs everything we need for our lab:
# - Mininet (for the network topology)
# - Ryu (SDN controller)
# - Tools like hping3, nmap, iperf3 for attacks and testing
# - Python packages
#
# How to use (run inside your Ubuntu 20.04 VM):
# 1) chmod +x install.sh
# 2) ./install.sh
#
# Last updated: May 18, 2026

# Exit if any command fails
set -euo pipefail

# Colors for nice output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Helper functions to print messages
info() { echo -e "${GREEN}[install]${NC} $*"; }
warn() { echo -e "${YELLOW}[warning]${NC} $*"; }


# Step 1: Update system and install basic packages
info "Updating package lists..."
sudo apt-get update -qq

info "Installing Mininet, Open vSwitch, and other network tools..."
sudo apt-get install -y \
    mininet \
    openvswitch-switch \
    hping3 \
    nmap \
    iperf3 \
    curl \
    git \
    python3-pip \
    python3-dev \
    --no-install-recommends

# Make sure Open vSwitch service is enabled and running for Mininet
sudo systemctl enable openvswitch-switch
sudo systemctl start openvswitch-switch
info "Open vSwitch is now running..."


# Step 2: Install Ryu SDN Controller
info "Installing Ryu SDN framework..."

# [!] Ryu has compatibility issues with newer eventlet on Ubuntu 20.04
# It works with an older version
pip3 install --user \
    ryu \
    "eventlet==0.30.3" \
    "oslo.config" \
    "six"

# Ryu puts binaries in ~/.local/bin, so we add it to PATH if not already there
if ! grep -q 'local/bin' ~/.bashrc; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
    export PATH="$HOME/.local/bin:$PATH"
    info "Added ~/.local/bin to PATH in ~/.bashrc"
fi

# Check if Ryu installed correctly
if command -v ryu-manager &>/dev/null; then
    info "[!] ryu-manager found: $(ryu-manager --version 2>&1 | head -1)"
else
    warn "ryu-manager not in PATH yet. Run: source ~/.bashrc"
fi


# Step 3 Install Python dependencies
info "Installing Python dependencies for sdn-fl-detector..."
# This reads from requirements.txt in the current folder
pip3 install --user -r requirements.txt


# 4. Verify Mininet installation
info "Verifying Mininet installation..."
if sudo mn --version &>/dev/null; then
    info "[!] Mininet: $(sudo mn --version 2>&1)"
else
    warn "Mininet check failed."
fi


# 5. Quick test to make sure Mininet works
info "[Wait] Running Mininet connectivity test..."
sudo mn --test pingall 2>&1 | tail -5
sudo mn -c 2>/dev/null || true  # clean up any leftover Mininet stuff


# 6. Display output 
echo ""
echo -e "${GREEN}+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+${NC}"
echo -e "${GREEN}          Installation complete! ${NC}"
echo -e "${GREEN}+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+${NC}"
echo ""
echo "Next steps for the lab:"
echo ""
echo "Terminal 1 — Start Ryu controller:"
echo "ryu-manager mininet/ryu_collector.py --observe-links"
echo ""
echo "Terminal 2 — Start Mininet topology:"
echo "sudo python mininet/topology.py --time 120"
echo ""
echo "Terminal 3 — Monitor data collection:"
echo "watch -n 5 wc -l data/live_client*.csv"
echo ""
echo "After data collection, train and run detection:"
echo "python cli.py train-local --data data/live_client1.csv --out models/live_c1.pkl"
echo "python cli.py federated-aggregate --models 'models/live_*.pkl' --out models/live_global.pkl"
echo "python cli.py detect --model models/live_global.pkl --data data/live_client1.csv --top-n 10"
echo ""
echo "EoF"