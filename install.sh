#!/usr/bin/env bash
# install.sh — Ubuntu 20.04 setup for SDN Federated Anomaly Detection Lab
#
# This script installs everything needed for the lab:
#   - Mininet from source
#   - Ryu SDN controller
#   - Tools: hping3, nmap, iperf3
#
# TODO:
#   chmod +x install.sh
#   ./install.sh
#
# Last updated: May 18, 2026

set -euo pipefail

GREEN='\033[1;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[install]${NC} $*"; }
warn() { echo -e "${YELLOW}[warning]${NC} $*"; }

# Step 1: System packages

info "Updating package lists..."
sudo apt-get update -qq

info "Installing system tools..."
sudo apt-get install -y \
    openvswitch-switch \
    hping3 \
    nmap \
    iperf3 \
    curl \
    git \
    python3-pip \
    python3-dev \
    python-is-python3 \
    build-essential \
    help2man \
    --no-install-recommends

# Ensure Open vSwitch is running (required by Mininet)
sudo systemctl enable openvswitch-switch
sudo systemctl start  openvswitch-switch
info "[!] Open vSwitch running"

# Step 2: Mininet from source (Python 3)
# The apt version of Mininet on Ubuntu 20.04 installs under Python 2.7.
# We need the source version for Python 3 compatibility.

info "Installing Mininet from source (Python 3)..."

# Clone into home directory to avoid conflicting with the sdn_mininet/ folder
if [ ! -d "$HOME/mininet-src" ]; then
    git clone https://github.com/mininet/mininet.git "$HOME/mininet-src"
fi

cd "$HOME/mininet-src"
git checkout 2.3.1b4

# Install Python package
sudo python3 setup.py install

# Build and install mnexec binary
sudo make install

cd -   # return to previous directory

# Verify
if sudo python3 -c "import mininet" 2>/dev/null; then
    info "[!] Mininet (Python 3) installed successfully"
else
    warn "Mininet import failed. Check the source install above for errors."
fi

# Step 3: Ryu SDN framework
# Note: eventlet 0.30.2 is required; newer versions break Ryu on Python 3.8

info "Installing Ryu SDN framework..."
pip3 install --user \
    ryu \
    "eventlet==0.30.2" \
    "oslo.config" \
    "six"

# Add ~/.local/bin to PATH if not already there
if ! grep -q 'local/bin' ~/.bashrc; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
    info "Added ~/.local/bin to PATH in ~/.bashrc"
fi
export PATH="$HOME/.local/bin:$PATH"

# Verify
if command -v ryu-manager &>/dev/null; then
    info "[!] ryu-manager found"
else
    warn "ryu-manager not in PATH. Run: source ~/.bashrc"
fi

# Step 4: Python dependencies

info "Installing Python dependencies..."
pip3 install --user -r requirements.txt
sudo pip3 install scapy

# Step 5: Quick Mininet self-test

info "Running Mininet connectivity self-test..."
sudo mn --test pingall 2>&1 | tail -5
sudo mn -c 2>/dev/null || true

# Display results

echo ""
echo -e "${GREEN}------------------------------------------------${NC}"
echo -e "${GREEN}  --> Installation is complete!${NC}"
echo -e "${GREEN}------------------------------------------------${NC}"
echo ""
echo "Next steps:"
echo ""
echo "In Terminal 1 — Start Ryu controller:"
echo -e "${YELLOW}[bash->]${NC}  ryu-manager sdn_mininet/ryu_collector.py --observe-links"
echo ""
echo "In Terminal 2 — Start Mininet topology:"
echo -e "${YELLOW}[bash->]${NC}   sudo python3 sdn_mininet/topology.py --time 120 --attack"
echo ""
echo "In Terminal 3 — Watch flows accumulate:"
echo -e "${YELLOW}[bash->]${NC}   watch -n 5 wc -l data/live_client*.csv"
echo ""
echo "  After collection — train and detect:"
echo "    python3 cli.py train-local --data data/live_client1.csv --out models/live_c1.pkl --client-id live_c1"
echo "    python3 cli.py train-local --data data/live_client2.csv --out models/live_c2.pkl --client-id live_c2"
echo "    python3 cli.py train-local --data data/live_client3.csv --out models/live_c3.pkl --client-id live_c3"
echo "    python3 cli.py federated-aggregate --models 'models/live_*.pkl' --out models/live_global.pkl"
echo "    python3 cli.py detect --model models/live_global.pkl --data data/live_client2.csv --top-n 10"
echo ""
