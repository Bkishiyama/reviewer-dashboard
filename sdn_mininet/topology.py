"""
mininet/topology.py: SDN Lab Topology for Mininet

Creates a 3-switch topology where each switch represents a different
"organization" (federated client).  Hosts generate both benign and
attack traffic so the Ryu collector captures a realistic mix.

See README for topology.

Traffic generated:
Benign  : iperf3 TCP/UDP streams, ping, curl-like HTTP
DDoS    : hping3 SYN flood from h4 -> h1
Scan    : nmap port scan from h6 -> h1..h5

Useage:
  sudo python mininet/topology.py [--attack]
    --attack   also launch attack traffic generators (default: benign only)
    --time N   run for N seconds (default: 60)

Requirements (installed by install.sh):
  Mininet, hping3, nmap, iperf3
"""

import argparse
import sys
import time

from mininet.log import setLogLevel, info
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo
from mininet.util import dumpNodeConnections


# Topology definition
# Three switches (one per federated client), each with two hosts.
# Switches are connected in a line: s1 - s2 - s3.
class FederatedSDNTopo(Topo):
    def build(self):
        # Switches (one per "client organization")
        s1 = self.addSwitch("s1", dpid="0000000000000001")
        s2 = self.addSwitch("s2", dpid="0000000000000002")
        s3 = self.addSwitch("s3", dpid="0000000000000003")

        # Inter-switch links
        self.addLink(s1, s2)
        self.addLink(s2, s3)

        # Hosts — 2 per switch
        h1 = self.addHost("h1", ip="10.0.0.1/8", mac="00:00:00:00:01:01")
        h2 = self.addHost("h2", ip="10.0.0.2/8", mac="00:00:00:00:01:02")
        h3 = self.addHost("h3", ip="10.0.0.3/8", mac="00:00:00:00:02:01")
        h4 = self.addHost("h4", ip="10.0.0.4/8", mac="00:00:00:00:02:02")
        h5 = self.addHost("h5", ip="10.0.0.5/8", mac="00:00:00:00:03:01")
        h6 = self.addHost("h6", ip="10.0.0.6/8", mac="00:00:00:00:03:02")

        # Host ↔ switch links
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s2)
        self.addLink(h4, s2)
        self.addLink(h5, s3)
        self.addLink(h6, s3)


# Traffic generators - Launch benign background traffic between hosts.
# Uses iperf3 (TCP + UDP) and ping to generate realistic flow diversity.
# All commands run in the background (&) so Mininet stays interactive.
def start_benign_traffic(net, duration: int):
    h1 = net.get("h1")
    h2 = net.get("h2")
    h3 = net.get("h3")
    h5 = net.get("h5")

    info("[!] Starting benign traffic generators\n")

    # iperf3 server on h1 (TCP + UDP)
    h1.cmd("iperf3 -s -D --logfile /tmp/iperf3_server.log")
    time.sleep(0.5)

    # h2 -> h1: TCP stream (simulates normal data transfer)
    h2.cmd(f"iperf3 -c 10.0.0.1 -t {duration} -i 5 "
           f"--logfile /tmp/iperf3_h2_tcp.log &")

    # h3 -> h1: UDP stream (simulates video/VoIP)
    h3.cmd(f"iperf3 -c 10.0.0.1 -u -b 1M -t {duration} -i 5 "
           f"--logfile /tmp/iperf3_h3_udp.log &")

    # h5 -> h1: repeated pings (simulates keepalives / monitoring)
    h5.cmd(f"ping -i 1 -c {duration} 10.0.0.1 > /tmp/ping_h5.log 2>&1 &")

    # h2 -> h3: lightweight TCP connection (simulates interorg traffic)
    h3.cmd("python3 -m http.server 8080 > /tmp/http_server.log 2>&1 &")
    h2.cmd(f"for i in $(seq 1 {duration // 3}); do "
           f"  curl -s http://10.0.0.3:8080 > /dev/null; sleep 3; done &")

    info("[!] iperf3 TCP/UDP, ping, HTTP traffic started\n")


# Launch attack traffic from designated attacker hosts.
# Labels are NOT automatically set in the CSV; you set them manually
# by noting the time window, or by running benign and attack phases separately.
def start_attack_traffic(net, duration: int):
    h4 = net.get("h4")   # DDoS attacker
    h6 = net.get("h6")   # port scanner

    info("[!] Starting Attack traffic generators\n")

    # DDoS: SYN flood from h4 -> h1
    # hping3: sends TCP SYN packets at high rate, spoofing source IPs
    # -S = SYN flag, --flood = max rate, -V = verbose, --rand-source = spoof src
    # Rate-limited here (--interval u10000 = 100 pkt/s) to avoid VM overload
    info("[!] DDoS SYN flood: h4 -> h1 (10.0.0.1:80)\n")
    h4.cmd(
        f"timeout {duration} hping3 -S -p 80 "
        f"--interval u10000 --rand-source "
        f"10.0.0.1 > /tmp/hping3_ddos.log 2>&1 &"
    )

    # Port scan: h6 scans all hosts
    # nmap SYN scan across the /24 ranges; slow timing (-T2) keeps it visible
    # in flow stats without overwhelming the controller
    info("[!] Port scan: h6 -> 10.0.1.0/24 and 10.0.2.0/24\n")
    h6.cmd(
        "nmap -sS -T2 -p 1-1024 "
        "10.0.0.0/8 "
        "> /tmp/nmap_scan.log 2>&1 &"
    )

    info("[!] DDoS (hping3) and port scan (nmap) started\n")
    info("[!] Remember: set label=1 for flows captured during this window\n")


# Convenience: print the time window so you can post-label the CSV rows.
# In a real deployment, timestamp the CSV and do:
# df.loc[df['timestamp'] > attack_start, 'label'] = 1
def label_attack_flows(net):
    info(f"\n*** Attack window started at: {time.strftime('%Y-%m-%dT%H:%M:%S')}\n")
    info("    Record this timestamp. After the run, use scripts/label_window.py\n"
         "    to update the CSV rows within this window to label=1.\n\n")


# Post-processing helper hint
LABEL_SCRIPT_HINT = """
After traffic generation, label the attack flows:

  python sdn_mininet/label_window.py \\
    --file data/live_client2.csv \\
    --start "2026-05-18T10:05:00" \\
    --end   "2026-05-18T10:10:00" \\
    --label 1
"""


def run(run_attacks: bool = False, duration: int = 60):
    setLogLevel("info")

    topo = FederatedSDNTopo()
    net  = Mininet(
        topo=topo,
        controller=RemoteController("ryu", ip="127.0.0.1", port=6633),
        autoSetMacs=False,
    )

    info("[!] Starting network\n")
    net.start()

    info("[!] Topology connections:\n")
    dumpNodeConnections(net.hosts)

    info("[!] Testing basic connectivity (ping all pairs)\n")
    net.pingAll()

    time.sleep(2)  # let the controller learn MACs

    # Start traffic
    start_benign_traffic(net, duration)

    if run_attacks:
        time.sleep(5)  # a few seconds of benign-only to establish baseline
        label_attack_flows(net)
        start_attack_traffic(net, duration - 5)

    info(f"\n[!] Running for {duration}s — Ryu is collecting flow stats\n")
    info("[!] Watch data/live_client*.csv grow in real time:\n")
    info("watch -n 5 wc -l data/live_client*.csv\n\n")

    time.sleep(duration)

    info("[!] Stopping network\n")
    net.stop()

    if run_attacks:
        info(LABEL_SCRIPT_HINT)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Mininet topology for SDN FL anomaly detection lab"
    )
    parser.add_argument("--attack", action="store_true",
                        help="Also launch DDoS and port-scan attack traffic")
    parser.add_argument("--time",   type=int, default=60,
                        help="Traffic duration in seconds (default: 60)")
    args = parser.parse_args()

    run(run_attacks=args.attack, duration=args.time)
