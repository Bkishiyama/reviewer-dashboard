from __future__ import annotations
#!/usr/bin/env python3

""" sdn_mininet/mitigator.py
SDN Mitigation Engine (Tool 4)
Purpose: This module executes the operator-approved mitigation action after the user
reviews and approves an alert in the HITL dashboard. Once the user approves the action,
the system mitigates the SDN control actions.
The design is a two-path approach
Path A: Ryu REST API
Sends a JSON request to Ryu controller's REST API. In turn, installs an OFPFlowMod on 
the target switch. This is the preferred way to do SDN mitigation, i.e., through the 
controller. Ryu's built-in ofctl_rest app exposes POST /stats/flowentry/add.
Path B: Raw OpenFlow socket
If the Ryu REST endpoint is not reachable, e.g. ryu_collector.py is not running or 
ofctl_rest is not loaded, mitigator.py falls back to the same raw OpenFlow approach 
used in injector.py. It will connect directly to the switch's passive listener 
(ptcp:6654 on s1) and send a binary FlowMod message. This fallback reuses the OFP 
constants and packet-builder functions from injector.py. It is NOT the Tool 3 attack,
the cookie, priority, and log messages are clearly seen as a legitimate HITL 
mitigation from the rogue injection.
Actions:
BLOCK: install a permanent DROP rule for the offending src IP
THROTTLE: install a rate-limiting rule (meter-based, if switch supports it;
otherwise falls back to a lower-priority DROP with short idle timeout)
UNBLOCK: delete a previously installed DROP rule for a src IP
Mitigation log: Every action, success or failure, is added to results/mitigator.log so the 
user has a full audit trail of every SDN change made by Tool 4.
Usage (called by dashboard/app.py after operator approves an alert):
from sdn_mininet.mitigator import Mitigator, MitigationResult
m = Mitigator()
result = m.block(
    src_ip = "10.0.0.4",
    dst_port = 80,
    protocol = "tcp",
    dpid = 1,
    alert_id = "a1b2c3d4",
)
print(result.summary())
"""

import json
import logging
import os
import socket
import struct
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)

# Configuration — mirrors topology.py and ryu_collector.py

# Ryu REST API (ofctl_rest app, standard port)
RYU_REST_HOST = os.environ.get("RYU_REST_HOST", "127.0.0.1")
RYU_REST_PORT = int(os.environ.get("RYU_REST_PORT", "8080"))

# OVS passive listeners — topology.py sets a dedicated ptcp port per
# switch so the raw-OpenFlow fallback can target the correct dpid instead
# of always landing on s1 regardless of which switch the alert is for.
OVS_SWITCH_IP = os.environ.get("OVS_SWITCH_IP", "127.0.0.1")

# dpid -> ptcp port (must match the ports configured in topology.py)
DPID_TO_OVS_PORT = {
    1: int(os.environ.get("OVS_SWITCH_PORT_S1", "6654")),
    2: int(os.environ.get("OVS_SWITCH_PORT_S2", "6655")),
    3: int(os.environ.get("OVS_SWITCH_PORT_S3", "6656")),
}
DEFAULT_OVS_PORT = DPID_TO_OVS_PORT[1]  # fallback for unknown dpid

# Host IP -> the switch that host is physically attached to (its ingress switch).
# A DROP rule only stops traffic on a switch the traffic actually traverses, and
# the surest place to stop a flood is the attacker's own ingress switch. The dpid
# carried on an Alert is merely the switch whose CSV happened to record the flow,
# which for multi-hop paths can be a downstream switch the source never enters --
# installing there yields a rule with n_packets=0 that blocks nothing. Must match
# the host-to-switch wiring in sdn_mininet/topology.py.
IP_TO_DPID = {
    "10.0.0.1": 1,  # h1  -> s1
    "10.0.0.2": 1,  # h2  -> s1
    "10.0.0.7": 1,  # h7  -> s1
    "10.0.0.3": 2,  # h3  -> s2
    "10.0.0.4": 2,  # h4  -> s2
    "10.0.0.5": 3,  # h5  -> s3
    "10.0.0.6": 3,  # h6  -> s3
}

# Flow rule parameters for HITL mitigations
HITL_COOKIE = 0xFEEDFACECAFE0004  # identifies Tool 4 rules in ovs-ofctl output
HITL_PRIORITY = 30000  # below injector.py (40000) but above normal (1)
IDLE_TIMEOUT_S = 300  # 5-minute idle timeout on BLOCK rules
HARD_TIMEOUT_S = 0  # no hard timeout by default

# Audit log path
MITIGATION_LOG_PATH = os.environ.get(
    "MITIGATION_LOG_PATH", "results/mitigator.log"
)

# OpenFlow 1.3 constants; consistent with injector.py
OFP_VERSION = 0x04
OFPT_HELLO = 0
OFPT_FEATURES_REQUEST = 5
OFPT_FEATURES_REPLY = 6
OFPT_FLOW_MOD = 14
OFPT_ROLE_REQUEST = 24
OFPT_ROLE_REPLY = 25
OFPFC_ADD = 0
OFPFC_DELETE = 3
OFPFC_DELETE_STRICT = 4
OFPMT_OXM = 1
OFPXMC_OPENFLOW_BASIC = 0x8000
OXM_FIELD_ETH_TYPE = 5
OXM_FIELD_IP_PROTO = 10
OXM_FIELD_IPV4_SRC = 11
OXM_FIELD_TCP_DST = 14
OXM_FIELD_UDP_DST = 16
OXM_FIELD_ETH_SRC = 4
OFPP_ANY = 0xFFFFFFFF
OFPG_ANY = 0xFFFFFFFF
OFP_NO_BUFFER = 0xFFFFFFFF
OFPCR_ROLE_EQUAL = 1

# IP protocol numbers
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMP = 1

PROTOCOL_MAP = {
    "tcp": PROTO_TCP,
    "udp": PROTO_UDP,
    "icmp": PROTO_ICMP,
    "ethernet": PROTO_TCP,   # fallback for L2-only collector rows
}


# Result dataclass
class MitigationAction(str, Enum):
    BLOCK = "block"
    THROTTLE = "throttle"
    UNBLOCK = "unblock"


class MitigationStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"  # e.g. IP already blocked

"""
Record of one mitigation attempt, written to the audit log and
returned to the dashboard for display.
"""
@dataclass
class MitigationResult:
    alert_id: str
    action: MitigationAction
    status: MitigationStatus
    src_ip: str
    dst_port: int
    protocol: str
    dpid: int
    method: str   # "ryu_rest" or "raw_openflow"
    timestamp: float = field(default_factory=time.time)
    error: Optional[str] = None
    rule_cookie: int = HITL_COOKIE

    @property
    def timestamp_str(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp))

    def summary(self) -> str:
        ok = "🟢" if self.status == MitigationStatus.SUCCESS else "🔴"
        return (
            f"[{ok}] {self.action.value.upper()} {self.src_ip} "
            f"→ port {self.dst_port}/{self.protocol} "
            f"on switch dpid={self.dpid} "
            f"via {self.method} "
            f"[alert={self.alert_id}] "
            f"at {self.timestamp_str}"
            + (f" - ERROR: {self.error}" if self.error else "")
        )

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "action": self.action.value,
            "status": self.status.value,
            "src_ip": self.src_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "dpid": self.dpid,
            "method": self.method,
            "timestamp": self.timestamp,
            "timestamp_str": self.timestamp_str,
            "error": self.error,
            "rule_cookie": hex(self.rule_cookie),
        }


# Mitigator class
"""
Executes SDN mitigation actions on behalf of the HITL dashboard. Tries the Ryu REST API first. 
If that fails, due to controller not running, ofctl_rest not loaded, network error, falls back 
to a raw OpenFlow socket connection to the switch's passive listener.
"""
class Mitigator:
    def __init__(
        self,
        ryu_host: str = RYU_REST_HOST,
        ryu_port: int = RYU_REST_PORT,
        ovs_ip: str = OVS_SWITCH_IP,
        log_path: str = MITIGATION_LOG_PATH,
        prefer_rest: bool = True,
    ):
        self.ryu_host = ryu_host
        self.ryu_port = ryu_port
        self.ovs_ip = ovs_ip
        self.log_path = log_path
        self.prefer_rest = prefer_rest

        os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)

    
    """  Public API 
    Install a DROP flow rule for traffic from src_ip to dst_port. The rule is permanent 
    (idle_timeout=IDLE_TIMEOUT_S, hard_timeout=0) and carries HITL_COOKIE so it can be identified in:
    ovs-ofctl dump-flows s1 -O OpenFlow13
    Priority is HITL_PRIORITY (30000) and above normal forwarding rules (priority 1) but below Tool 3 is 
    rogue injection (priority 40000), so a HITL block can be overridden in demos without changing constants.
    """
    def block(
        self,
        src_ip: str,
        dst_port: int,
        protocol: str,
        dpid: int,
        alert_id: str,
    ) -> MitigationResult:
        logger.info(
            "[Mitigator] BLOCK requested: src=%s dst_port=%d proto=%s dpid=%d alert=%s",
            src_ip, dst_port, protocol, dpid, alert_id,
        )

        result = self._execute(
            action = MitigationAction.BLOCK,
            src_ip = src_ip,
            dst_port = dst_port,
            protocol = protocol,
            dpid = dpid,
            alert_id = alert_id,
            command = OFPFC_ADD,
        )
        self._log(result)
        return result

    """
    Install a short-lived DROP rule, idle_timeout=60s, as a traffic throttle. The rule expires 
    if traffic stops, so it self-cleans. Note: True rate limiting requires meter support, 
    OF 1.3 meters. OVS in Mininet supports meters but the current topology does not configure 
    them, so this is implemented as a time-limited DROP. The dashboard labels this "throttle" 
    to distinguish it from a permanent block.
    """
    def throttle(
        self,
        src_ip: str,
        dst_port: int,
        protocol: str,
        dpid: int,
        alert_id: str,
    ) -> MitigationResult:
        logger.info(
            "[Mitigator] THROTTLE requested: src=%s dst_port=%d proto=%s dpid=%d alert=%s",
            src_ip, dst_port, protocol, dpid, alert_id,
        )

        result = self._execute(
            action = MitigationAction.THROTTLE,
            src_ip = src_ip,
            dst_port = dst_port,
            protocol = protocol,
            dpid = dpid,
            alert_id = alert_id,
            command = OFPFC_ADD,
            idle_timeout= 60,
        )
        self._log(result)
        return result

    """
    Remove a previously installed BLOCK or THROTTLE rule for src_ip. Uses OFPFC_DELETE_STRICT with 
    the HITL_COOKIE to avoid accidentally deleting normal forwarding rules that happen to match the same fields.
    """
    def unblock(
        self,
        src_ip: str,
        dst_port: int,
        protocol: str,
        dpid: int,
        alert_id: str,
    ) -> MitigationResult:
        logger.info(
            "[Mitigator] UNBLOCK requested: src=%s dst_port=%d dpid=%d alert=%s",
            src_ip, dst_port, dpid, alert_id,
        )

        result = self._execute(
            action = MitigationAction.UNBLOCK,
            src_ip = src_ip,
            dst_port = dst_port,
            protocol = protocol,
            dpid = dpid,
            alert_id = alert_id,
            command = OFPFC_DELETE_STRICT,
        )
        self._log(result)
        return result

    """
    Convenience wrapper that takes an Alert object directly from hitl.py
    so dashboard/app.py does not need to unpack fields manually.
    Parameters
    alert : Alert
      A fully-constructed Alert from src/hitl.py.
    action : MitigationAction
      Which mitigation to apply (default: BLOCK).
    """
    def from_alert(
        self,
        alert,
        action: MitigationAction = MitigationAction.BLOCK,
    ) -> MitigationResult:
        # Prefer the source host's own ingress switch over the dpid recorded on
        # the alert -- see IP_TO_DPID above for why the alert's dpid can point at
        # a switch the attacker's traffic never crosses.
        dpid = IP_TO_DPID.get(alert.src_ip) or (alert.dpid if alert.dpid else 1)

        if action == MitigationAction.BLOCK:
            return self.block(
                src_ip = alert.src_ip,
                dst_port = alert.dst_port,
                protocol = alert.protocol,
                dpid = dpid,
                alert_id = alert.alert_id,
            )
        elif action == MitigationAction.THROTTLE:
            return self.throttle(
                src_ip = alert.src_ip,
                dst_port = alert.dst_port,
                protocol = alert.protocol,
                dpid = dpid,
                alert_id = alert.alert_id,
            )
        elif action == MitigationAction.UNBLOCK:
            return self.unblock(
                src_ip = alert.src_ip,
                dst_port = alert.dst_port,
                protocol = alert.protocol,
                dpid = dpid,
                alert_id = alert.alert_id,
            )
        else:
            raise ValueError(f"Unknown MitigationAction: {action}")

    
    """  Internal execution
    Try Ryu REST first, fall back to raw OpenFlow socket.
    Returns a MitigationResult regardless of which path succeeded.
    """
    def _execute(
        self,
        action: MitigationAction,
        src_ip: str,
        dst_port: int,
        protocol: str,
        dpid: int,
        alert_id: str,
        command: int,
        idle_timeout: int = IDLE_TIMEOUT_S,
        hard_timeout: int = HARD_TIMEOUT_S,
    ) -> MitigationResult:

        if self.prefer_rest:
            result = self._via_ryu_rest(
                action, src_ip, dst_port, protocol, dpid, alert_id,
                command, idle_timeout, hard_timeout,
            )
            if result.status == MitigationStatus.SUCCESS:
                return result
            logger.warning(
                "[Mitigator] Ryu REST failed (%s) — trying raw OpenFlow fallback",
                result.error,
            )

        # Fallback: raw OpenFlow socket to OVS passive listener
        return self._via_raw_openflow(
            action, src_ip, dst_port, protocol, dpid, alert_id,
            command, idle_timeout, hard_timeout,
        )

   
    """  Path A: Ryu REST API 
    Install or delete a flow rule via Ryu's ofctl_rest API.
    POST /stats/flowentry/add    -> install a rule
    POST /stats/flowentry/delete_strict -> remove a specific rule
    The JSON body follows Ryu's ofctl_rest schema. Ryu translates this into an OFPFlowMod and sends it to the switch.
    """
    def _via_ryu_rest(
        self,
        action: MitigationAction,
        src_ip: str,
        dst_port: int,
        protocol: str,
        dpid: int,
        alert_id: str,
        command: int,
        idle_timeout: int,
        hard_timeout: int,
    ) -> MitigationResult:
        proto_num = PROTOCOL_MAP.get(protocol.lower(), PROTO_TCP)

        # Build OXM match fields
        match: dict = {
            "dl_type": "0x0800",          # IPv4
            "nw_proto": str(proto_num),   # TCP or UDP
        }
        if src_ip and src_ip not in ("unknown", "0.0.0.0", ""):
            if _is_mac_address(src_ip):
                match["dl_src"] = src_ip
            else:
                match["nw_src"] = src_ip
      
        if dst_port > 0:
            if proto_num == PROTO_TCP:
                match["tp_dst"] = str(dst_port)
            elif proto_num == PROTO_UDP:
                match["tp_dst"] = str(dst_port)
            # ICMP does not use tp_dst

        # DELETE_STRICT endpoint removes by exact match + priority + cookie
        if command == OFPFC_DELETE_STRICT:
            endpoint = f"http://{self.ryu_host}:{self.ryu_port}/stats/flowentry/delete_strict"
            body = {
                "dpid": dpid,
                "cookie": HITL_COOKIE,
                "priority": HITL_PRIORITY,
                "match": match,
            }
        else:
            # ADD empty actions list = DROP in OpenFlow
            endpoint = f"http://{self.ryu_host}:{self.ryu_port}/stats/flowentry/add"
            body = {
                "dpid": dpid,
                "cookie": HITL_COOKIE,
                "priority": HITL_PRIORITY,
                "idle_timeout": idle_timeout,
                "hard_timeout": hard_timeout,
                "match": match,
                "actions": [],   # no actions = DROP
            }

        try:
            payload = json.dumps(body).encode("utf-8")
            req = urllib.request.Request(
                endpoint,
                data = payload,
                headers = {"Content-Type": "application/json"},
                method = "POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                resp_body = resp.read().decode("utf-8", errors="replace")
                logger.info(
                    "[Mitigator] Ryu REST %s → %s: %s",
                    action.value, endpoint, resp_body[:120],
                )

            return MitigationResult(
                alert_id  = alert_id,
                action = action,
                status = MitigationStatus.SUCCESS,
                src_ip = src_ip,
                dst_port = dst_port,
                protocol = protocol,
                dpid = dpid,
                method = "ryu_rest",
            )

        except (urllib.error.URLError, OSError) as exc:
            return MitigationResult(
                alert_id  = alert_id,
                action = action,
                status = MitigationStatus.FAILED,
                src_ip = src_ip,
                dst_port = dst_port,
                protocol = protocol,
                dpid = dpid,
                method = "ryu_rest",
                error = str(exc),
            )

     
    """ Path B: Raw OpenFlow socket
    Send a raw OFPFlowMod to the switch via ptcp:6654 (s1's passive listener).
    This mirrors the approach in injector.py but:
    - Uses HITL_COOKIE, not ATTACKER_COOKIE, so it is distinguishable
    - Matches on src IP + dst port, injector.py matches only dst port
    - Priority is 30000 but injector.py uses 40000
    - Action is DROP via empty instruction set
    - Logs clearly as a HITL defensive action
    """
    def _via_raw_openflow(
        self,
        action: MitigationAction,
        src_ip: str,
        dst_port: int,
        protocol: str,
        dpid: int,
        alert_id: str,
        command: int,
        idle_timeout: int,
        hard_timeout: int,
    ) -> MitigationResult:

      
        ovs_port = DPID_TO_OVS_PORT.get(dpid, DEFAULT_OVS_PORT)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.ovs_ip, ovs_port))
        except OSError as exc:
            return MitigationResult(
                alert_id  = alert_id,
                action    = action,
                status    = MitigationStatus.FAILED,
                src_ip    = src_ip,
                dst_port  = dst_port,
                protocol  = protocol,
                dpid      = dpid,
                method    = "raw_openflow",
                error     = f"TCP connect to {self.ovs_ip}:{ovs_port} (dpid={dpid}) failed: {exc}",
            )
      
        try:
            #Handshake 
            sock.sendall(_build_hello())
            _read_until(sock, OFPT_HELLO)

            sock.sendall(_build_features_request())
            _read_until(sock, OFPT_FEATURES_REPLY)

            # Request EQUAL role so OVS accepts our FlowMod while Ryu holds MASTER
            sock.sendall(_build_role_request())
            _read_until(sock, OFPT_ROLE_REPLY)

            # Send FlowMod 
            proto_num = PROTOCOL_MAP.get(protocol.lower(), PROTO_TCP)
            flowmod = _build_flowmod(
                src_ip = src_ip,
                dst_port = dst_port,
                proto_num = proto_num,
                command = command,
                priority = HITL_PRIORITY,
                idle_timeout = idle_timeout,
                hard_timeout = hard_timeout,
            )
            sock.sendall(flowmod)

            logger.info(
                "[Mitigator] Raw OF FlowMod sent: action=%s src=%s dst_port=%d "
                "dpid=%d cookie=0x%x priority=%d",
                action.value, src_ip, dst_port, dpid,
                HITL_COOKIE, HITL_PRIORITY,
            )

            return MitigationResult(
                alert_id = alert_id,
                action = action,
                status = MitigationStatus.SUCCESS,
                src_ip = src_ip,
                dst_port = dst_port,
                protocol = protocol,
                dpid = dpid,
                method = "raw_openflow",
            )

        except (OSError, struct.error) as exc:
            return MitigationResult(
                alert_id = alert_id,
                action = action,
                status = MitigationStatus.FAILED,
                src_ip = src_ip,
                dst_port = dst_port,
                protocol = protocol,
                dpid = dpid,
                method = "raw_openflow",
                error = str(exc),
            )
        finally:
            try:
                sock.close()
            except OSError:
                pass

    # Audit log
    # Append one line to the mitigation audit log
    def _log(self, result: MitigationResult) -> None:
        try:
            with open(self.log_path, "a") as f:
                f.write(f"[{result.timestamp_str}] {result.summary()}\n")
        except OSError as exc:
            logger.warning("[Mitigator] Could not write to log %s: %s", self.log_path, exc)


# Raw OpenFlow packet builders (consistent with injector.py)
# Standard 8-byte OpenFlow 1.3 header
def _ofp_header(msg_type: int, body: bytes, xid: int = 1) -> bytes:
    return struct.pack("!BBHI", OFP_VERSION, msg_type, 8 + len(body), xid) + body


def _build_hello() -> bytes:
    return _ofp_header(OFPT_HELLO, b"", xid=1)


def _build_features_request() -> bytes:
    return _ofp_header(OFPT_FEATURES_REQUEST, b"", xid=2)


def _build_role_request() -> bytes:
    body = struct.pack("!IIQ", OFPCR_ROLE_EQUAL, 0, 0)
    return _ofp_header(OFPT_ROLE_REQUEST, body, xid=4)

# Encode one OXM TLV field (Type-Length-Value)
def _oxm_tlv(field_id: int, value: bytes, hasmask: bool = False) -> bytes:
    mask_bit = 1 if hasmask else 0
    return (
        struct.pack(
            "!HBB",
            OFPXMC_OPENFLOW_BASIC,
            (field_id << 1) | mask_bit,
            len(value),
        )
        + value
    )

# Convert a dotted-decimal IP string to 4 bytes
def _ip_to_bytes(ip_str: str) -> bytes:
    parts = [int(p) for p in ip_str.split(".")]
    return struct.pack("!BBBB", *parts)

# Convert a colon-separated MAC string to 6 bytes
def _mac_to_bytes(mac_str: str) -> bytes:
    parts = [int(p, 16) for p in mac_str.split(":")]
    if len(parts) != 6:
        raise ValueError(f"Not a MAC address: {mac_str}")
    return struct.pack("!BBBBBB", *parts)

"""
True if value looks like a MAC address (xx:xx:xx:xx:xx:xx), False if it looks like an IPv4 address.
The live collector (ryu_collector.py) stores MAC addresses in the src_ip/dst_ip fields for L2 flows, 
while Tool 3's synthetic demo data uses real dotted-decimal IPv4 addresses in the same fields. This
lets mitigator.py build the correct OXM match type for either source.
"""
def _is_mac_address(value: str) -> bool:
    parts = value.split(":")
    return len(parts) == 6 and all(
        len(p) == 2 and all(c in "0123456789abcdefABCDEF" for c in p)
        for p in parts
    )

"""
Build the OXM match block for the HITL FlowMod.

The live collector (ryu_collector.py) stores MAC addresses in the src_ip field for L2-only flows; 
Tool 3's synthetic demo data uses real IPv4 addresses in the same field. This builds the correct OXM
match type for whichever one is actually present, instead of always assuming IPv4 and silently 
dropping the source match on a MAC string.
Matches:
  - EtherType = 0x0800 (IPv4) — always included for TCP/UDP/ICMP demos
  - IP protocol = proto_num (TCP=6, UDP=17, ICMP=1)
  - Source = IPv4 (OXM_FIELD_IPV4_SRC) or MAC (OXM_FIELD_ETH_SRC),
    whichever src_ip actually looks like
  - TCP/UDP dst port = dst_port (if > 0 and not ICMP)
"""
def _build_oxm_match(
    src_ip:    str,
    dst_port:  int,
    proto_num: int,
) -> bytes:
    oxm = b""
    oxm += _oxm_tlv(OXM_FIELD_ETH_TYPE, struct.pack("!H", 0x0800))
    oxm += _oxm_tlv(OXM_FIELD_IP_PROTO, struct.pack("!B", proto_num))

    if src_ip and src_ip not in ("unknown", "0.0.0.0", ""):
        if _is_mac_address(src_ip):
            try:
                oxm += _oxm_tlv(OXM_FIELD_ETH_SRC, _mac_to_bytes(src_ip))
            except (ValueError, struct.error):
                logger.warning(
                    "[Mitigator] Could not encode MAC src_ip=%s — skipping source match",
                    src_ip,
                )
        else:
            try:
                oxm += _oxm_tlv(OXM_FIELD_IPV4_SRC, _ip_to_bytes(src_ip))
            except (ValueError, struct.error):
                logger.warning(
                    "[Mitigator] Could not encode IPv4 src_ip=%s — skipping source match",
                    src_ip,
                )

    if dst_port > 0 and proto_num != PROTO_ICMP:
        field = OXM_FIELD_TCP_DST if proto_num == PROTO_TCP else OXM_FIELD_UDP_DST
        oxm += _oxm_tlv(field, struct.pack("!H", dst_port))

    match_len = 4 + len(oxm)
    raw = struct.pack("!HH", OFPMT_OXM, match_len) + oxm
    # Pad to 8-byte boundary
    return raw + b"\x00" * ((8 - len(raw) % 8) % 8)


"""
Build a complete OFPFlowMod message. For BLOCK / THROTTLE (OFPFC_ADD):
- No actions / instructions → DROP
- Uses HITL_COOKIE to distinguish from Tool 3 rogue rules
For UNBLOCK (OFPFC_DELETE_STRICT):
  - Matches cookie + priority + OXM fields to remove exact rule
"""
def _build_flowmod(
    src_ip: str,
    dst_port: int,
    proto_num: int,
    command: int,
    priority: int,
    idle_timeout: int,
    hard_timeout: int,
) -> bytes:
    match_block = _build_oxm_match(src_ip, dst_port, proto_num)

    # Fixed FlowMod body (40 bytes)
    # Layout: cookie(8) cookie_mask(8) table_id(1) command(1)
    #   idle_timeout(2) hard_timeout(2) priority(2)
    #   buffer_id(4) out_port(4) out_group(4) flags(2) pad(2)
    fixed = struct.pack(
        "!QQBBHHHIIIHxx",
        HITL_COOKIE,  # cookie — identifies HITL rules
        0,  # cookie_mask
        0,  # table_id
        command,  # OFPFC_ADD / OFPFC_DELETE_STRICT
        idle_timeout,
        hard_timeout,
        priority,
        OFP_NO_BUFFER,
        OFPP_ANY,
        OFPG_ANY,
        0,  # flags
    )

    # No instructions/actions block for DROP
    # (For DELETE_STRICT, Ryu ignores out_port=OFPP_ANY + no actions = delete any)
    body = fixed + match_block

    return _ofp_header(OFPT_FLOW_MOD, body, xid=5)

"""
Read OpenFlow messages from the socket until one with expected_type arrives.
Returns the raw message bytes, or None on timeout/error. Mirrors the same helper in injector.py.
"""
def _read_until(sock: socket.socket, expected_type: int, max_bytes: int = 4096) -> Optional[bytes]:
    try:
        data = sock.recv(max_bytes)
        while data:
            if len(data) < 4:
                break
            msg_type = data[1]
            if msg_type == expected_type:
                return data
            # Read next message if this one wasn't what we wanted
            data = sock.recv(max_bytes)
    except OSError:
        pass
    return None


# Verification helper used by dashboard and CLI
"""
Run ovs-ofctl dump-flows and filter for HITL_COOKIE rules. Returns the raw ovs-ofctl output lines 
matching Tool 4 rules, or an error string if ovs-ofctl is not available. Used by the dashboard's 
/api/verify endpoint and the CLI's python3 cli.py hitl --verify flag.
"""
def verify_rule_installed(dpid: int = 1) -> str:
    import subprocess
    switch = f"s{dpid}"
    cookie_hex = hex(HITL_COOKIE)
    try:
        result = subprocess.run(
            ["sudo", "-n", "ovs-ofctl", "dump-flows", switch, "-O", "OpenFlow13"],
            capture_output = True,
            text = True,
            timeout = 5,
        )
        lines = [
            line for line in result.stdout.splitlines()
            if cookie_hex in line.lower() or "hitl" in line.lower()
        ]
        if not lines:
            return (
                f"No active Tool 4 (HITL) block rules on {switch} — nothing is "
                f"currently being dropped by an operator-approved mitigation. "
                f"(Other switch flows are unaffected; this check only looks for "
                f"cookie {cookie_hex}.)"
            )
        return "\n".join(lines)
    except FileNotFoundError:
        return "ovs-ofctl not found — run this inside the Mininet VM."
    except subprocess.TimeoutExpired:
        return f"ovs-ofctl timed out querying {switch}."
