from __future__ import annotations
#!/usr/bin/env python3

""" sdn_mininet/topology.py 
Purpose: To build the Mininet topology within an SDN 
This topology is used for Tools 1, 2, 3, and 4.
Summary:
Tool 1: FL anomaly detection -> ryu_collector.py polls flow stats -> CSVs
Tool 2: Poisoning defense -> h6 runs poisoned_host.py; cleaned by sanitizer.py
Tool 3: FlowMod injection -> attacker (h7) runs injector.py; HTTP traffic dropped on s1
Tool 4: This if to display results to the user.
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
- External attack mode (Kali -> IoTGoat through Mininet):
  - sudo python3 sdn_mininet/topology.py --time 120 --external
  - Kali (192.168.100.3) attacks IoTGoat (192.168.100.2) via br-iot bridge <---- I set up static addresses.
  - Traffic routes through s1 so Ryu sees and records it
  - Dashboard detects and blocks Kali's attack.
IP address of Mininet br-iot is 192.168.100.211. <---This is not a static address <----- for now.
"""

import argparse
import os
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
For external attack mode (--external), hgw is added to s1 as a gateway
host that bridges Mininet to the IoTGoat network via br-iot.
"""
class FederatedSDNTopo(Topo):
    def build(self, external=False):
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

        # Tool 3: attacker host added to s1
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

        # External attack mode: gateway host bridges Mininet to IoTGoat network.
        # hgw sits on s1 and forwards traffic between the Mininet 10.0.0.0/8
        # network and the IoTGoat/Kali network (192.168.100.0/24) via br-iot.
        # Kali (192.168.100.3) -> br-iot -> veth -> s1 -> hgw -> IoTGoat (192.168.100.2)
        if external:
            hgw = self.addHost("hgw",
                ip="10.0.0.10/8",
                mac="00:00:00:00:01:10")
            self.addLink(hgw, s1)


""" Traffic Generators
This functions is used to generate normal traffic across the network.
Use iperf3 (TCP + UDP), ping, and HTTP so the Ryu collector Tool 1 captures 
a realistic data flow. In Tool 3, I added h2 to run an HTTP server on port 80.
This gives the injector a target to block.
"""
def start_benign_traffic(net, duration: int):
    # use a wrapper to create a Linux host to generate traffic using iperf
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

    # Tool 3: HTTP server on h2 port 80
    # h2 serves HTTP on port 80.  Before injection, h1 gets normal traffic. 
    # For Tool Tool 3, if executed, the injected FlowMod drops all TCP/80 traffic on s1. 
    # h1's requests will time out but pings to h2 continues working.
    h2.cmd("python3 -m http.server 80 > /tmp/http_h2_port80.log 2>&1 &")

    # h1 to h2: periodic HTTP requests establishes a flow baseline for Tool 1
    h1.cmd(
        f"for i in $(seq 1 {duration // 5}); do "
        f"  curl -s --max-time 3 http://10.0.0.2/ > /dev/null; sleep 5; done &"
    )

    info("[!] iperf3 TCP/UDP, ping, HTTP (port 80 + 8080) traffic started\n")


"""
This function launches malicious traffic from hosts h4 and h6.  
Labels are set manually after the run using label_window.py.
h4 = DDoS SYN flood, h6 = port scanner and FL poisoner.
"""
def start_attack_traffic(net, duration: int):
    h4 = net.get("h4")   # Tool 2: DDoS attacker
    h6 = net.get("h6")   # Tool 2: port scanner / FL poisoner

    info("[!] Starting Tool 2 attack traffic generators\n")

    # Start the DDoS: SYN flood from h4 -> h1 
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


"""  This is for CSC 842 IoTGoat vulnerabilities
External attack mode: set up gateway host hgw to bridge Mininet to the
IoTGoat network (192.168.100.0/24) via the br-iot bridge interface.
Network path:
  Kali (192.168.100.3) -> br-iot -> veth-iot/veth-s1 -> s1 (Ryu sees it)
  -> hgw (10.0.0.10) -> IoTGoat (192.168.100.2)
Ryu records all traffic passing through s1, so the dashboard can detect
and block Kali's attack even though Kali is on an external network.
"""
def setup_external_gateway(net):
    hgw = net.get("hgw")
    info("[!] Setting up external gateway (hgw) for IoTGoat/Kali connectivity\n")
    # Create veth pair connecting OVS s1 to the br-iot bridge.
    # veth-s1 plugs into OVS, veth-iot plugs into br-iot.
    os.system("sudo ip link add veth-s1 type veth peer name veth-iot 2>/dev/null || true")
    os.system("sudo ip link set veth-s1 up")
    os.system("sudo ip link set veth-iot up")

    # Add veth-iot to the br-iot bridge so the IoTGoat/Kali network
    # is reachable from OVS s1 via the veth pair.
    os.system("sudo brctl addif br-iot veth-iot 2>/dev/null || true")

    # Add veth-s1 to OVS switch s1 so Ryu sees all external traffic.
    os.system("sudo ovs-vsctl add-port s1 veth-s1 2>/dev/null || true")

    # Enable IP forwarding on hgw so it can route between Mininet
    # (10.0.0.0/8) and the IoTGoat network (192.168.100.0/24).
    hgw.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")

    # Add route to IoTGoat subnet via hgw's interface.
    hgw.cmd("ip route add 192.168.100.0/24 dev hgw-eth0")

    # NAT on the Ubuntu host so Mininet hosts can reach IoTGoat.
    # MASQUERADE rewrites the source IP so IoTGoat's replies route back correctly.
    os.system("sudo iptables -t nat -A POSTROUTING -s 10.0.0.0/8 -o br-iot -j MASQUERADE")
    os.system("sudo iptables -A FORWARD -i s1 -o br-iot -j ACCEPT")
    os.system("sudo iptables -A FORWARD -i br-iot -o s1 -j ACCEPT")

    info("[!] Gateway hgw (10.0.0.10) -> IoTGoat (192.168.100.2) ready\n")
    info("[!] On Kali, run: sudo ip route add 10.0.0.0/8 via 192.168.100.2\n")
    info("[!] Verify: mininet> hgw ping -c 3 192.168.100.2\n")


# Print the attack-window timestamp for post-hoc CSV labeling
def label_attack_flows(net):
    Y = "\033[93m"  # yellow
    R = "\033[0m"   # reset

    attack_start = time.time()

    info(
        f"\n{Y}[!] Attack window START: {time.strftime('%Y-%m-%dT%H:%M:%S')}{R}\n"
        f"{Y}--> Record this timestamp. After the run, use:{R}\n"
        f"{Y}    python3 sdn_mininet/label_window.py \\\n"
        f"      --file data/live_client2.csv --all --label 1{R}\n\n"
    )

    return attack_start


LABEL_SCRIPT_HINT = """
After traffic generation, label the attack flows using the timestamps in /tmp/attack_window.txt:
  python3 sdn_mininet/label_window.py \
    --file data/live_client2.csv \
    --attack-window /tmp/attack_window.txt
"""


#  Main
def run(run_attacks: bool = False, run_inject: bool = False,
        run_external: bool = False, duration: int = 60):
    setLogLevel("info")
    topo = FederatedSDNTopo(external=run_external)
    net = Mininet(
        topo=topo,
        controller=RemoteController("ryu", ip="127.0.0.1", port=6633),
        switch=OVSSwitch,
        autoSetMacs=False,
    )

    info("[!] Starting network\n")
    net.start()

    # Tool 3: configure OVS passive listener on s1 (ptcp:6654)
    # ptcp puts the switch into server mode so a raw-socket client (the injector, 
    # or Tool 4's mitigator fallback) can open a direct OpenFlow ession with that 
    # specific switch. The primary Ryu connection on port 6633 is preserved and unaffected.
    s1 = net.get("s1")
    info("[!] Tool 3: enabling OVS passive listener on s1 (ptcp:6654)\n")
    s1.cmd(
        "ovs-vsctl set-controller s1 "
        "tcp:127.0.0.1:6633 "  # keep existing Ryu connection
        "ptcp:6654"  # add passive listener for injector
    )
    s1.cmd("ovs-vsctl set bridge s1 protocols=OpenFlow13")

    # Tool 4: extend the same passive-listener pattern to s2/s3 so the mitigator's 
    # raw-OpenFlow fallback can target alerts on dpid=2/dpid=3 directly, not just dpid=1.  
    # Ports 6655/6656 are dedicated to s2/s3 respectively, distinct from s1's 6654 
    # so a stale dpid mapping can never silently land a FlowMod on the wrong switch.
    s2 = net.get("s2")
    info("[!] Tool 4: enabling OVS passive listener on s2 (ptcp:6655)\n")
    s2.cmd(
        "ovs-vsctl set-controller s2 "
        "tcp:127.0.0.1:6633 "
        "ptcp:6655"
    )
    s2.cmd("ovs-vsctl set bridge s2 protocols=OpenFlow13")

    s3 = net.get("s3")
    info("[!] Tool 4: enabling OVS passive listener on s3 (ptcp:6656)\n")
    s3.cmd(
        "ovs-vsctl set-controller s3 "
        "tcp:127.0.0.1:6633 "
        "ptcp:6656"
    )
    s3.cmd("ovs-vsctl set bridge s3 protocols=OpenFlow13")

    s1.cmd("ovs-vsctl set bridge s1 fail-mode=standalone")
    info("[!] Topology connections:\n")
    dumpNodeConnections(net.hosts)

    info("[!] Testing basic connectivity (ping all pairs)\n")
    net.pingAll()

    time.sleep(2)   # let the controller learn MACs

    # External attack mode: set up the gateway host after the network starts
    # so OVS s1 is available for the veth port attachment.
    if run_external:
        setup_external_gateway(net)

    # Start traffic
    start_benign_traffic(net, duration)

    if run_attacks:
        info(LABEL_SCRIPT_HINT)
        time.sleep(5)
        attack_start = label_attack_flows(net)
        start_attack_traffic(net, duration - 5)

        attack_end = time.time()
        info(f"\033[93m[!] Attack window END:   {time.strftime('%Y-%m-%dT%H:%M:%S')}\033[0m\n")

        # Save both timestamps for labeling
        with open("/tmp/attack_window.txt", "w") as f:
            f.write(f"{attack_start},{attack_end}\n")

    if run_inject:
        # Wait so Tool 1 records some normal HTTP flow data,
        # making the before/after contrast visible in live_client1.csv.
        time.sleep(10)
        start_inject_attack(net)
    # show proof of concept for Tool 3
    info(f"\n[!] Running for {duration}s — Ryu is collecting flow stats\n")
    info("[!] Watch data/live_client*.csv grow:\n")
    info("[*] watch -n 5 wc -l data/live_client*.csv\n\n")
    info("[!] Tool 3 verify commands (in Mininet CLI below):\n")
    info("[*] mininet> h1 curl --max-time 3 http://10.0.0.2/  # times out\n")
    info("[*] mininet> h1 ping -c 3 10.0.0.2  # succeeds\n")
    info("[*] mininet> sh ovs-ofctl dump-flows s1 -O OpenFlow13\n\n")

    # provide options when Kali attacks IoTGoat at IP 192.168.100.2      
    if run_external:
        info("[!] External attack mode active:\n")
        info("[*] From Kali: hping3 -S --flood -V -p 80 192.168.100.2\n")
        info("[*] From Kali: nmap -sS -p 1-1000 192.168.100.2\n")
        info("[*] Verify in Mininet CLI: hgw ping -c 3 192.168.100.2\n\n")

    # Go to interactive CLI so that I can run manual tests
    CLI(net)

    info("[!] Stopping network\n")

    # Clean up external gateway and remove veth pair, bridge port, and iptables rules upon exit
    if run_external:
        info("[!] Cleaning up external gateway\n")
        os.system("sudo ovs-vsctl del-port s1 veth-s1 2>/dev/null || true")
        os.system("sudo brctl delif br-iot veth-iot 2>/dev/null || true")
        os.system("sudo ip link del veth-s1 2>/dev/null || true")
        os.system("sudo iptables -t nat -D POSTROUTING -s 10.0.0.0/8 -o br-iot -j MASQUERADE 2>/dev/null || true")
        os.system("sudo iptables -D FORWARD -i s1 -o br-iot -j ACCEPT 2>/dev/null || true")
        os.system("sudo iptables -D FORWARD -i br-iot -o s1 -j ACCEPT 2>/dev/null || true")

    # stop network      
    net.stop()


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
    # added for tool 5; the kali linux attacker
    parser.add_argument(
        "--external", action="store_true",
        help="Tool 4: enable external attack mode -> routes Kali/IoTGoat traffic through s1"
    )
    parser.add_argument(
        "--time", type=int, default=60,
        help="Traffic duration in seconds (default: 60)"
    )
    args = parser.parse_args()

    run(run_attacks=args.attack, run_inject=args.inject,
        run_external=args.external, duration=args.time)
