#!/usr/bin/env bash

# install-22.04.sh
# Ubuntu 22.04 setup for SDN Federated Anomaly Detection Lab
# This script runs my lab on Ubuntu 22.04/Python 3.10. 
# Ubuntu 20.04/Python 3.8 use different packages.
# - Mininet from source
# - Ryu SDN controller (faucetsdn fork, Python 3.10 compatible)
# - Tools: hping3, nmap, iperf3
# TODO:
# chmod +x install-22.04.sh
# ./install-22.04.sh
# Last updated: June 19, 2026

set -euo pipefail

GREEN='\033[1;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[install]${NC} $*"; }
warn() { echo -e "${YELLOW}[warning]${NC} $*"; }

# Step 1: System packages
info "[*] Updating package lists"
sudo apt-get update -qq

info "[*] Installing system tools"
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
# Ubuntu 22.04 ships Python 3.10 by default, which is fine for Mininet.
# `make install` can fail with an EggMetadata/pip error on 22.04 because
# pip can't uninstall the egg that `setup.py install` creates. Work
# around it by removing any existing egg before reinstalling, then
# falling back to a manual mnexec build/install if `make install` still
# fails.

info "[*] Installing Mininet from source (Python 3)"

if [ ! -d "$HOME/mininet-src" ]; then
    git clone https://github.com/mininet/mininet.git "$HOME/mininet-src"
fi

cd "$HOME/mininet-src"
git checkout 2.3.1b4

# Remove pre-existing egg metadata to avoid the pip/EggMetadata
# uninstall conflict on Ubuntu 22.04
sudo find /usr/local/lib -name "mininet*" -exec rm -rf {} + 2>/dev/null || true
sudo find /usr/lib -name "mininet*.egg*" -exec rm -rf {} + 2>/dev/null || true

# Install Python package
sudo python3 setup.py install

# Build and install mnexec binary. Install first, an fall back to
# a manual build if pip's egg-uninstall step fails
if ! sudo make install; then
    warn "make install failed (egg conflict) -> building mnexec manually"
    cc -Wall -Wextra mnexec.c -o mnexec
    sudo install -D mnexec /usr/bin/mnexec
fi

cd -   # return to previous directory

# Verify
if sudo python3 -c "import mininet" 2>/dev/null; then
    info "[!] Mininet (Python 3) installed successfully"
else
    warn "Mininet import failed. Check the source install above for errors."
fi

 
# Step 3: Ryu SDN framework
# The `pip install ryu` + eventlet combination breaks on Python 3.10. 
# The faucetsdn fork patches these for Python 3.10, but its setup.py pins eventlet==0.31.1, 
# which itself does not fully work on 3.10. Installing with --no-deps and then pinning 
# eventlet/dnspython manually is the combination confirmed to work end-to-end:
# eventlet==0.35.2
# dnspython==2.1.0
# --no-deps also skips Ryu's other declared dependencies, so they are installed 
# explicitly below (netaddr, msgpack, routes, tinyrpc, oslo.config). pip's conflict 
# warnings about eventlet and packaging versions can be IGNORED.  <----------------


info "[*] Installing Ryu SDN framework (faucetsdn fork, Python 3.10 compatible)"
pip3 install --user --no-deps git+https://github.com/faucetsdn/ryu.git

info "[*] Installing pinned eventlet + dnspython (required for Python 3.10)"
pip3 install --user \
    "eventlet==0.35.2" \
    "dnspython==2.1.0"

info "[*] Installing Ryu's remaining runtime dependencies"
pip3 install --user \
    netaddr \
    msgpack \
    routes \
    "tinyrpc==1.0.4" \
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
info "[*] Installing Python dependencies"
pip3 install --user -r requirements.txt
sudo pip3 install scapy

# Step 5: Quick Mininet self-test
info "Running Mininet connectivity self-test"
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
echo "In Terminal 1: Start Ryu controller (simple_switch_13 is needed"
echo "on Ubuntu 22.04 since ryu_collector.py only collects stats and"
echo "does not perform MAC learning on its own):"
echo -e "${YELLOW}[bash->]${NC}  ryu-manager sdn_mininet/ryu_collector.py ryu.app.simple_switch_13 --observe-links"
echo ""
echo "In Terminal 2 — Start Mininet topology:"
echo -e "${YELLOW}[bash->]${NC}   sudo python3 sdn_mininet/topology.py --time 120 --attack"
echo ""
echo "In Terminal 3 — Watch flows accumulate:"
echo -e "${YELLOW}[bash->]${NC}   watch -n 5 wc -l data/live_client*.csv"
echo ""
echo "  After collection -> train and detect:"
echo "    python3 cli.py train-local --data data/live_client1.csv --out models/live_c1.pkl --client-id live_c1"
echo "    python3 cli.py train-local --data data/live_client2.csv --out models/live_c2.pkl --client-id live_c2"
echo "    python3 cli.py train-local --data data/live_client3.csv --out models/live_c3.pkl --client-id live_c3"
echo "    python3 cli.py federated-aggregate --models 'models/live_*.pkl' --out models/live_global.pkl"
echo "    python3 cli.py detect --model models/live_global.pkl --data data/live_client2.csv --top-n 10"
echo ""
