from __future__ import annotations
#!/usr/bin/env python3

""" sdn_mininet/topology.py 
Purpose: To build the Mininet topology within an SDN 
This topology is used for Tools 1, 2, and 3.
Summary:
Tool 1: FL anomaly detection -> ryu_collector.py polls flow stats -> CSVs
Tool 2: Poisoning defense -> h6 runs poisoned_host.py; cleaned by sanitizer.py
Tool 3: FlowMod injection -> attacker (h7) runs injector.py; HTTP traffic dropped on s1
h7 is added to the topology <-> s1; h7 runs injector.py
h2 has HTTP on port 80 and the injection target s1
s1 gets a passive OVS listener on ptcp:6654 -> allows injector to connect
to the switch with a second controller session
## OpenFlow controller port
Tools 1 & 2 use port 6633.  The sniffer in injector.py matches this. 
Usage
- Terminal 1: Ryu with FL collector and Tool 2poisoning guard
  - ryu-manager sdn_mininet/ryu_collector.py --observe-links
- Terminal 2: start topology (benign only)
  - sudo python3 sdn_mininet/topology.py --time 120
- Terminal 2: with all attacks
  sudo python3 sdn_mininet/topology.py --time 120 --attack --inject
- Terminal 3: Tool 3 - inject FlowMod (or run from Mininet CLI)
  - python3 sdn_mininet/injector.py
- Terminal 4: watch Tool 1 data accumulate
  - watch -n 5 wc -l data/live_client*.csv
-  Verify Tool 3 in Mininet CLI
  - mininet> h1 curl --max-time 3 http://10.0.0.2/  # times out (injected)
  - mininet> h1 ping -c 3 10.0.0.2  # succeeds - evasion proof
  - mininet> sh ovs-ofctl dump-flows s1 -O OpenFlow13  # shows the rogue rule
"""

import argparse
import subprocess
import sys
import time
from mininet.cli import CLI
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo
from mininet.util import dumpNodeConnections


""" Topology Definition
Three switches: s1<–>s2<–>s3, each one represents one federated client organization.
s1: {h1, h2} —> FL client1 -> one Isolation Forest
s2: {h3, h4 (DDoS)}  —> FL client2 org -> one Isolation Forest
s3: {h5, h6 (poison)}  —> FL client3 org -> one Isolation Forest
For Tool 3, I add h7 as the attacker to s1:
h7 shares s1 so it can inject FlowMods that affects HTTP traffic 
between h1 <-> h2 as both are on the same switch.
"""
class FederatedSDNTopo(Topo):
    def build(self):
        # Switches
        s1 = self.addSwitch("s1", dpid="0000000000000001")
        s2 = self.addSwitch("s2", dpid="0000000000000002")
        s3 = self.addSwitch("s3", dpid="0000000000000003")

        # links between switches
        self.addLink(s1, s2)
        self.addLink(s2, s3)

        # Hosts same as in Tools 1 & 2
        h1 = self.addHost("h1", ip="10.0.0.1/8", mac="00:00:00:00:01:01")
        h2 = self.addHost("h2", ip="10.0.0.2/8", mac="00:00:00:00:01:02")
        h3 = self.addHost("h3", ip="10.0.0.3/8", mac="00:00:00:00:02:01")
        h4 = self.addHost("h4", ip="10.0.0.4/8", mac="00:00:00:00:02:02")
        h5 = self.addHost("h5", ip="10.0.0.5/8", mac="00:00:00:00:03:01")
        h6 = self.addHost("h6", ip="10.0.0.6/8", mac="00:00:00:00:03:02")

        # Tool 3: attacker host added ─
        # h7 is placed on s1 and injects FlowMod; affects h1/h2 traffic.
        # h7 uses a separate MAC/IP to avoid collisions with existing hosts.
        h7 = self.addHost("h7", ip="10.0.0.7/8", mac="00:00:00:00:01:07")

        # Links between hosts to switchs 
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s2)
        self.addLink(h4, s2)
        self.addLink(h5, s3)
        self.addLink(h6, s3)
        self.addLink(h7, s1)   # Tool 3: attacker added to s1


""" *** Traffic Generators ***
Launch normal traffic across the topology.
Uses iperf3 (TCP + UDP), ping, and HTTP so the Ryu collector
Tool 1 continues to capture a realistic data flow.
Tool 3 -> I added h2 to run an HTTP server on port 80.
This gives the injector a target to block.
"""
def start_benign_traffic(net, duration: int):
    h1 = net.get("h1")
    h2 = net.get("h2")
    h3 = net.get("h3")
    h5 = net.get("h5")

    info("[!] Starting benign traffic generators\n")

    # iperf3 server on h1 (receives TCP + UDP from other hosts)
    h1.cmd("iperf3 -s -D --logfile /tmp/iperf3_server.log")
    time.sleep(0.5)

    # h2 to h1: create TCP stream that simulates normal data transfer
    h2.cmd(
        f"iperf3 -c 10.0.0.1 -t {duration} -i 5 "
        f"--logfile /tmp/iperf3_h2_tcp.log &"
    )

    # h3 to h1: UDP stream that simulates video or VoIP
    h3.cmd(
        f"iperf3 -c 10.0.0.1 -u -b 1M -t {duration} -i 5 "
        f"--logfile /tmp/iperf3_h3_udp.log &"
    )

    # h5 to h1: repeated pings to simulate keepalives or monitoring
    h5.cmd(f"ping -i 1 -c {duration} 10.0.0.1 > /tmp/ping_h5.log 2>&1 &")

    # h2 & h3 traffic: normal HTTP traffic to simulates web requests in either direction
    h3.cmd("python3 -m http.server 8080 > /tmp/http_h3.log 2>&1 &")
    h2.cmd(
        f"for i in $(seq 1 {duration // 3}); do "
        f"  curl -s http://10.0.0.3:8080 > /dev/null; sleep 3; done &"
    )

    # (Added)Tool 3: HTTP server on h2 port 80
    # h2 serves HTTP on port 80.  Before injection, h1 gets pages
    # normally. After Tool 3 executes, the injected FlowMod drops all
    # TCP/80 traffic on s1. h1's requests will time out but pings
    # to h2 continues working - to show evasion proof.
    h2.cmd("python3 -m http.server 80 > /tmp/http_h2_port80.log 2>&1 &")

    # h1 to h2: periodic HTTP requests establishes a flow baseline for Tool 1
    h1.cmd(
        f"for i in $(seq 1 {duration // 5}); do "
        f"  curl -s --max-time 3 http://10.0.0.2/ > /dev/null; sleep 5; done &"
    )

    info("[!] iperf3 TCP/UDP, ping, HTTP (port 80 + 8080) traffic started\n")


"""
Tool's 2 attack traffic from designated attacker hosts.
Labels are set manually after the run using label_window.py.
h4 = DDoS SYN flood, h6 = port scanner remain from Tool 2.
"""
def start_attack_traffic(net, duration: int):
    h4 = net.get("h4")   # Tool 2: DDoS attacker
    h6 = net.get("h6")   # Tool 2: port scanner / FL poisoner

    info("[!] Starting Tool 2 attack traffic generators\n")

    # DDoS: SYN flood from h4 -> h1 (will limit rate for VM stability)
    info("[!] DDoS SYN flood: h4 -> h1 (10.0.0.1:80)\n")
    h4.cmd(
        f"timeout {duration} hping3 -S -p 80 "
        f"--interval u10000 --rand-source "
        f"10.0.0.1 > /tmp/hping3_ddos.log 2>&1 &"
    )

    # Port scan: h6 scans all hosts on the /8 range
    info("[!] Port scan: h6 -> 10.0.0.0/8\n")
    h6.cmd(
        "nmap -sS -T2 -p 1-1024 10.0.0.0/8 "
        "> /tmp/nmap_scan.log 2>&1 &"
    )

    info("[!] DDoS (hping3) and port scan (nmap) started\n")
    info("[!] Remember: set label=1 for flows captured during this window\n")


"""
Tool 3: run the FlowMod injector from h7.

h7 executes injector.py:
1. Sniffs loopback OF traffic on port 6633 to confirm the control channel
2. Connects to s1's passive listener (ptcp:6654)
3. Performs an OF v1.3 handshake
4. Injects a high-priority FlowMod -> drops TCP/80 traffic on s1

The --skip-sniff flag is used here because h7 runs inside Mininet's
network namespace and cannot sniff the host loopback.  The sniff phase
is still useful when running injector.py directly from the host terminal.
"""
def start_inject_attack(net):
    h7 = net.get("h7")
    info("[!] Tool 3: launching FlowMod injector from h7\n")
    # h7 connects to 127.0.0.1:6654. This resolves to the HOST loopback
    # because Mininet hosts share the host machine's network stack for
    # connections to 127.0.0.1.
    h7.cmd(
        "python3 sdn_mininet/injector.py "
        "--switch-ip 127.0.0.1 --switch-port 6654 "
        "--target-port 80 --priority 40000 "
        "--skip-sniff "
        "> /tmp/injector.log 2>&1 &"
    )
    info("[!] Injector launched — see /tmp/injector.log for output\n")

# Print the attack-window timestamp for post-hoc CSV labeling
def label_attack_flows(net):
    info(
        f"\n*** Attack window started at: {time.strftime('%Y-%m-%dT%H:%M:%S')}\n"
        "--> Record this timestamp. After the run, use:\n"
        "    python3 sdn_mininet/label_window.py \\\n"
        "      --file data/live_client2.csv --all --label 1\n\n"
    )


LABEL_SCRIPT_HINT = """
After traffic generation, label the attack flows:

  python3 sdn_mininet/label_window.py \\
    --file data/live_client2.csv \\
    --all --label 1
"""


#  Main
def run(run_attacks: bool = False, run_inject: bool = False, duration: int = 60):
    setLogLevel("info")
    topo = FederatedSDNTopo()
    net = Mininet(
        topo=topo,
        controller=RemoteController("ryu", ip="127.0.0.1", port=6633),
        switch=OVSSwitch,
        autoSetMacs=False,
    )

    info("[!] Starting network\n")
    net.start()

    # Added Tool 3: configure OVS passive listener on s1
    # ptcp:6654 puts s1 into server mode on port 6654 so the injector can
    # open a direct OpenFlow session with the switch.  The primary Ryu
    # connection on port 6633 is preserved and unaffected.
    s1 = net.get("s1")
    info("[!] Tool 3: enabling OVS passive listener on s1 (ptcp:6654)\n")
    s1.cmd(
        "ovs-vsctl set-controller s1 "
        "tcp:127.0.0.1:6633 "    # keep existing Ryu connection
        "ptcp:6654"              # add passive listener for injector
    )
    s1.cmd("ovs-vsctl set bridge s1 protocols=OpenFlow13")
    s1.cmd("ovs-vsctl set bridge s1 fail-mode=standalone")
    info("[!] Topology connections:\n")
    dumpNodeConnections(net.hosts)

    info("[!] Testing basic connectivity (ping all pairs)\n")
    net.pingAll()

    time.sleep(2)   # let the controller learn MACs

    # Start traffic
    start_benign_traffic(net, duration)

    if run_attacks:
        time.sleep(5)   # a few seconds of benign-only baseline
        label_attack_flows(net)
        start_attack_traffic(net, duration - 5)

    if run_inject:
        # Wait so Tool 1 records some normal HTTP flow data,
        # making the before/after contrast visible in live_client1.csv.
        time.sleep(10)
        start_inject_attack(net)

    info(f"\n[!] Running for {duration}s — Ryu is collecting flow stats\n")
    info("[!] Watch data/live_client*.csv grow:\n")
    info("[*] watch -n 5 wc -l data/live_client*.csv\n\n")
    info("[!] Tool 3 verify commands (in Mininet CLI below):\n")
    info("[*] mininet> h1 curl --max-time 3 http://10.0.0.2/  # times out\n")
    info("[*] mininet> h1 ping -c 3 10.0.0.2  # succeeds\n")
    info("[*] mininet> sh ovs-ofctl dump-flows s1 -O OpenFlow13\n\n")

    # Go to interactive CLI so that I can run manual tests
    CLI(net)

    info("[!] Stopping network\n")
    net.stop()

    if run_attacks:
        info(LABEL_SCRIPT_HINT)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Mininet topology for SDN FL anomaly detection + FlowMod injection lab"
    )
    parser.add_argument(
        "--attack", action="store_true",
        help="Tool 2: also launch DDoS and port-scan attack traffic (h4, h6)"
    )
    parser.add_argument(
        "--inject", action="store_true",
        help="Tool 3: also launch FlowMod injector from h7 -> drops HTTP on s1"
    )
    parser.add_argument(
        "--time", type=int, default=60,
        help="Traffic duration in seconds (default: 60)"
    )
    args = parser.parse_args()

    run(run_attacks=args.attack, run_inject=args.inject, duration=args.time)
