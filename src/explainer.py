from __future__ import annotations
#!/usr/bin/env python3

"""
src/explainer.py Human-Readable Alert Explanation Engine (Tool 4)
Purpose: This module is responsible for why the system deems the behavior as suspicious
It takes the raw FeatureDeviation objects, from hitl.py, and converts it into understandable 
text for non-experts. 
Two main outputs per alert:
1. explanation -> what the model saw, in simple terms
2. recommendation -> what the user should do 

The explanation logic works has two phases:
  Phase 1: Pattern matching
      Check for known attack signatures, e.g., DDoS, port scan, flow table exhaustion, based on 
      feature combinations and port/protocol context. If a known pattern matches, 
      use a understandable description.
  Phase 2: Feature-driven fallback
      If no pattern matches, describe the likely deviating features, e.g., packet rate was 12.3× 
      above the baseline and do not label it.
Usage: called by hitl.py, but can also be used directly
    from src.hitl import FeatureDeviation, Severity
    from src.explainer import build_explanation, build_recommendation
    explanation = build_explanation(top_devs, severity, protocol)
    recommendation = build_recommendation(severity, protocol, dst_port)
"""

import logging
from typing import Optional
from src.hitl import FeatureDeviation, Severity

logger = logging.getLogger(__name__)


# Well-known port map (for display in explanation text)
PORT_NAMES: dict[int, str] = {
    20: "FTP data",
    21: "FTP control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    6633: "OpenFlow",
    6653: "OpenFlow",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    27017: "MongoDB",
}

# Ports that are sensitive & flag in recommendation text
SENSITIVE_PORTS: set[int] = {
    22, 23, 25, 53, 80, 161, 389, 443, 445,
    1433, 3306, 3389, 5432, 6379, 6633, 6653, 27017,
}

# Ports typical of scanning behaviour, low + well-known services
SCAN_TARGET_PORTS: set[int] = {
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 3306, 3389, 8080,
}

# Ports where a tiny, single/few-packet, near-instant exchange is NORMAL
# protocol behavior (DNS query, DHCP lease, NTP sync) — not suspicious.
# Excluding these keeps _match_port_scan and _match_flow_table_exhaustion
# from firing on routine one-shot service traffic that is small and fast
# by design, not because it's a scan or a flood.
BENIGN_SINGLE_EXCHANGE_PORTS: set[int] = {53, 67, 68, 123}


# Pattern detection helpers
# Return the FeatureDeviation for a named feature, or None if absent
def _get_feature(devs: list[FeatureDeviation], name: str) -> Optional[FeatureDeviation]:
    for d in devs:
        if d.feature == name:
            return d
    return None

# Return the Z-score for a named feature, or 0.0 if not present
def _z(devs: list[FeatureDeviation], name: str) -> float:
    d = _get_feature(devs, name)
    return d.z_score if d else 0.0

# Return the observed value for a named feature, or 0.0 if not present
def _val(devs: list[FeatureDeviation], name: str) -> float:
    d = _get_feature(devs, name)
    return d.flow_value if d else 0.0

# Format a numeric value for human display, use K/M suffixes for large numbers
def _fmt_val(v: float) -> str:
    if v >= 1_000_000:
        return f"{v / 1_000_000:.1f}M"
    if v >= 1_000:
        return f"{v / 1_000:.1f}K"
    if v == int(v):
        return str(int(v))
    return f"{v:.2f}"

# Return 'port 80 (HTTP)' style label, or just 'port N' if unknown
def _port_label(port: int) -> str:
    name = PORT_NAMES.get(port)
    return f"port {port} ({name})" if name else f"port {port}"


# Pattern matchers
# Each returns a (matched: bool, label: str, detail: str) tuple.
# label = short attack type name shown in the alert header
# detail = one or two sentences describing the specific indicators
"""
DDoS signature: very high byte/packet counts, very short duration, targeting a small number of well-known ports.
From generate_data.py's _ddos_flows():
  bytes : 40,000–1,500,000
  packets : 500–5,000
  duration: 0.001–0.5 s  (very short)
"""
def _match_ddos(
    all_devs: list[FeatureDeviation],
    protocol: str,
    dst_port: int,
) -> tuple[bool, str, str]:
    bytes_z = _z(all_devs, "bytes")
    packets_z = _z(all_devs, "packets")
    duration_z = _z(all_devs, "duration")
    pkt_rate_z = _z(all_devs, "packet_rate")
    bytes_val  = _val(all_devs, "bytes")
    packets_val = _val(all_devs, "packets")
    duration_val = _val(all_devs, "duration")
    pkt_rate_val = _val(all_devs, "packet_rate")

    # Must have: high bytes OR high packets AND short duration
    high_volume = bytes_z > 2.0 or packets_z > 2.0
    short_lived = duration_z < -1.0 or duration_val < 1.0  # negative Z = below baseline
    high_rate = pkt_rate_z > 2.0

    if not (high_volume and (short_lived or high_rate)):
        return False, "", ""

    port_str = _port_label(dst_port) if dst_port > 0 else "the target host"

    detail = (
        f"This flow sent {_fmt_val(bytes_val)} bytes across "
        f"{_fmt_val(packets_val)} packets in only {duration_val:.3f}s — "
        f"a packet rate of {_fmt_val(pkt_rate_val)} packets/s. "
        f"The target was {port_str}. "
        f"This volume-to-duration ratio is characteristic of a volumetric "
        f"flood attack (SYN flood, UDP amplification, or similar)."
    )
    return True, "Potential DDoS / volumetric flood", detail

"""
Port scan signature: tiny packets, very short duration, single-packet flows, often TCP SYN only.
From generate_data.py's _port_scan_flows():
bytes: 40–120  (small probe packets)
packets: 1  (single SYN per flow)
duration: 0.0001–0.05 s
"""
def _match_port_scan(
    all_devs: list[FeatureDeviation],
    protocol: str,
    dst_port: int,
    src_port: int,
) -> tuple[bool, str, str]:
    bytes_val = _val(all_devs, "bytes")
    packets_val = _val(all_devs, "packets")
    duration_val = _val(all_devs, "duration")
    bpp_val = _val(all_devs, "bytes_per_packet")
    bytes_z = _z(all_devs, "bytes")
    packets_z = _z(all_devs, "packets")
    duration_z = _z(all_devs, "duration")

    # Must have: very small packets AND single/few-packet flows
    tiny_payload = bytes_val < 200 and bytes_z < -0.5
    single_pkt = packets_val <= 2
    instant = duration_val < 0.1

    if not (tiny_payload and (single_pkt or instant)):
        return False, "", ""

    if dst_port in BENIGN_SINGLE_EXCHANGE_PORTS:
        return False, "", ""

    proto_str = protocol.upper() if protocol else "TCP"
    port_str = _port_label(dst_port) if dst_port in SCAN_TARGET_PORTS else f"port {dst_port}"

    detail = (
        f"This flow carried only {_fmt_val(bytes_val)} bytes in "
        f"{_fmt_val(packets_val)} packet(s), completing in {duration_val:.4f}s. "
        f"Bytes-per-packet was {_fmt_val(bpp_val)}, well below any real data transfer. "
        f"The {proto_str} probe targeted {port_str}. "
        f"Single-packet, near-instant flows across many destination ports "
        f"are the defining fingerprint of an automated port scanner."
    )
    return True, "Potential port scan / reconnaissance", detail

"""
Flow table exhaustion (FTE) signature: many tiny, short-lived flows from random source IPs 
targeting random ports, designed to fill the switch's flow table and force table-miss 
CPU load on the controller.
From generate_data.py's _flow_table_exhaustion():
bytes: 40–500  (small)
packets: 1  (single packet per flow)
duration: 0.0001–0.1 s
src_ip: fully randomised (not visible at feature level, but packet_rate and bytes_per_packet 
patterns are distinctive)
"""
def _match_flow_table_exhaustion(
    all_devs: list[FeatureDeviation],
    protocol: str,
    dst_port: int,
) -> tuple[bool, str, str]:
    bytes_val = _val(all_devs, "bytes")
    packets_val = _val(all_devs, "packets")
    duration_val = _val(all_devs, "duration")
    bpp_val = _val(all_devs, "bytes_per_packet")
    bytes_z = _z(all_devs, "bytes")
    duration_z = _z(all_devs, "duration")

    # FTE looks like scan but bytes may be slightly larger, and the dst_port is typically 
    # also random, not in SCAN_TARGET_PORTS. We check for the combination of small payload
    # + instant duration + not-a-scan-port.
    tiny = bytes_val < 600 and bytes_z < 0
    instant = duration_val < 0.15
    one_pkt = packets_val <= 2

    if not (tiny and instant and one_pkt):
        return False, "", ""

    if dst_port in BENIGN_SINGLE_EXCHANGE_PORTS:
        return False, "", ""

    proto_str = protocol.upper() if protocol else "mixed protocol"

    detail = (
        f"This {proto_str} flow carried {_fmt_val(bytes_val)} bytes in a "
        f"single packet lasting {duration_val:.4f}s. "
        f"At {_fmt_val(bpp_val)} bytes per packet, no meaningful data was exchanged. "
        f"Flows with randomised source IPs and destination ports at this scale "
        f"are consistent with a flow table exhaustion attack — an adversary "
        f"flooding the SDN controller with table-miss events to degrade "
        f"forwarding performance and amplify CPU load."
    )
    return True, "Potential flow table exhaustion attack", detail

"""
Control-plane probe signature: traffic directed at OpenFlow ports (6633, 6653). 
In the Tool 3 injector, this is relevant as any host probing the controller port 
should be flagged immediately.
"""
def _match_control_plane_probe(
    dst_port: int,
    protocol: str,
    all_devs: list[FeatureDeviation],
) -> tuple[bool, str, str]:
    if dst_port not in {6633, 6653}:
        return False, "", ""

    bytes_val = _val(all_devs, "bytes")

    detail = (
        f"This {(protocol or 'TCP').upper()} flow targeted "
        f"{_port_label(dst_port)}, the SDN controller's OpenFlow management port. "
        f"Direct access to the controller channel from a non-controller host "
        f"is never expected in a correctly-configured network. "
        f"This may indicate a Tool 3-style FlowMod injection attempt or "
        f"reconnaissance of the control plane. "
        f"Flow size: {_fmt_val(bytes_val)} bytes."
    )
    return True, "Control-plane probe — OpenFlow port targeted", detail

"""
Catch-all for anomalous traffic to sensitive service ports when no specific attack pattern matched. 
Adds port context to the explanation. Only for MEDIUM or HIGH severity alerts to avoid noise.
"""
def _match_sensitive_port(
    dst_port: int,
    protocol: str,
    severity: Severity,
) -> tuple[bool, str, str]:

    if dst_port not in SENSITIVE_PORTS:
        return False, "", ""
    if severity == Severity.LOW:
        return False, "", ""

    detail = (
        f"The anomalous flow targeted {_port_label(dst_port)}, "
        f"a port associated with a sensitive network service. "
        f"Unusual traffic patterns on this port may indicate "
        f"brute-force, exploitation, or unauthorised access attempts."
    )
    return True, f"Anomalous traffic to {_port_label(dst_port)}", detail


# Severity header lines

_SEVERITY_HEADERS: dict[Severity, str] = {
    Severity.HIGH:   "HIGH SEVERITY — immediate review recommended",
    Severity.MEDIUM: "MEDIUM SEVERITY — elevated suspicion",
    Severity.LOW:    "LOW SEVERITY — minor anomaly flagged",
}

_SEVERITY_ICONS: dict[Severity, str] = {
    Severity.HIGH: "⚠",
    Severity.MEDIUM: "⚡",
    Severity.LOW: "ℹ",
}



"""  Public API
Generates understandable explanation shown in the operator dashboard.
The explanation structured:
[severity icon + header]
[attack pattern name, if a known pattern matched]
[one to two sentences describing the specific indicators]
[feature breakdown, i.e., top deviating features with Z-scores]
Parameters
top_devs : list[FeatureDeviation]
  The top 1–3 most-deviating features (pre-sorted by |Z-score|),
  as computed in hitl.py's Alert.from_detection_row().
severity : Severity
  Alert severity (HIGH / MEDIUM / LOW).
protocol : str
  Protocol string from the flow row (e.g. "tcp", "udp", "icmp").
dst_port : int
  Destination port of the anomalous flow.
src_port : int
  Source port of the anomalous flow.
all_devs : list[FeatureDeviation], optional
  Full list of all feature deviations (not just the top 3).
  Used by pattern matchers that need to check features not in top_devs.
  If None, top_devs is used for matching too.
Returns str
  Multi-line explanation text, suitable for display in the dashboard alert detail panel.
"""
def build_explanation(
    top_devs: list[FeatureDeviation],
    severity: Severity,
    protocol: str,
    dst_port: int = 0,
    src_port: int = 0,
    all_devs: Optional[list[FeatureDeviation]] = None,
) -> str:
    devs_for_matching = all_devs if all_devs is not None else top_devs
    proto = (protocol or "").strip().lower()
    icon = _SEVERITY_ICONS[severity]
    header = _SEVERITY_HEADERS[severity]

    # Layer 1: pattern matching

    pattern_name = ""
    pattern_detail = ""

    # Control-plane probe check first, highest priority
    matched, pattern_name, pattern_detail = _match_control_plane_probe(
        dst_port, proto, devs_for_matching
    )

    if not matched:
        matched, pattern_name, pattern_detail = _match_ddos(
            devs_for_matching, proto, dst_port
        )

    if not matched:
        matched, pattern_name, pattern_detail = _match_port_scan(
            devs_for_matching, proto, dst_port, src_port
        )

    if not matched:
        matched, pattern_name, pattern_detail = _match_flow_table_exhaustion(
            devs_for_matching, proto, dst_port
        )

    if not matched:
        matched, pattern_name, pattern_detail = _match_sensitive_port(
            dst_port, proto, severity
        )

    # Layer 2: feature-driven fallback
    if not matched or not pattern_detail:
        pattern_name = "Anomalous traffic pattern"
        pattern_detail = _feature_fallback(top_devs, proto, dst_port)

    # Build feature breakdown section 
    feature_lines = _build_feature_breakdown(top_devs)

    # Assemble final text
    parts = [
        f"{icon}  {header}",
        f"",
        f"Detection: {pattern_name}",
        f"",
        pattern_detail,
    ]

    if feature_lines:
        parts += [
            "",
            "Top contributing indicators:",
        ] + feature_lines

    explanation = "\n".join(parts)

    logger.debug(
        "[Explainer] Built explanation: severity=%s pattern=%s",
        severity.value, pattern_name,
    )

    return explanation

"""
Generate the user recommendation shown with the explanation. The recommendation 
has three choices. Decision enum values in hitl.py, so the operator knows exactly what
each button in the dashboard will do.
Parameters
severity : Severity
  Alert severity.
protocol : str
  Flow protocol.
dst_port : int
  Destination port of the anomalous flow.
src_ip : str
  Source IP of the anomalous flow
Returns str
 Plain-English recommendation with three labeled options.
"""
def build_recommendation(
    severity: Severity,
    protocol: str,
    dst_port: int = 0,
    src_ip: str = "",
) -> str:
    proto = (protocol or "").strip().lower()
    src_str = f"host {src_ip}" if src_ip and src_ip != "unknown" else "the source host"
    port_str = _port_label(dst_port) if dst_port > 0 else "the target"

    # Control-plane probe → always recommend immediate block
    if dst_port in {6633, 6653}:
        return (
            f"⛔  APPROVE (Block): Install an OpenFlow DROP rule to immediately "
            f"prevent {src_str} from reaching the controller on {port_str}. "
            f"Control-plane access by unexpected hosts is a critical threat.\n\n"
            f"👁  MONITOR: Continue recording flows from {src_str} without blocking. "
            f"Use this if you believe this is a misconfigured legitimate tool.\n\n"
            f"✕  IGNORE: Dismiss this alert. Use only if you have confirmed "
            f"this host is an authorised controller or management station."
        )

    if severity == Severity.HIGH:
        return (
            f"⛔  APPROVE (Block): Install a DROP flow rule to cut off traffic "
            f"from {src_str} immediately. The anomaly score and volume of "
            f"suspicious indicators strongly suggest active malicious behaviour. "
            f"Blocking now limits potential damage.\n\n"
            f"👁  MONITOR: Keep watching {src_str} without blocking. "
            f"Choose this if you want more evidence before acting, or if this "
            f"host may be running a legitimate high-volume job.\n\n"
            f"✕  IGNORE: Dismiss this alert as a false positive. "
            f"Recommended only if you can verify the traffic is expected "
            f"(e.g. a scheduled backup or authorised load test)."
        )

    if severity == Severity.MEDIUM:
        return (
            f"⛔  APPROVE (Block): Block traffic from {src_str} to {port_str}. "
            f"The pattern is suspicious but not definitive — review the "
            f"feature breakdown above before deciding.\n\n"
            f"👁  MONITOR: Flag {src_str} for close monitoring. "
            f"No immediate action; the system will continue collecting flows. "
            f"Escalate to APPROVE if the behaviour persists or worsens.\n\n"
            f"✕  IGNORE: Mark as a false positive. Useful if this traffic "
            f"matches a known maintenance window or test activity."
        )

    # LOW severity
    return (
        f"⛔  APPROVE (Block): Block {src_str}. Use only if additional context "
        f"(recent incidents, threat intelligence) supports this decision — the "
        f"anomaly score alone is low.\n\n"
        f"👁  MONITOR: Log and watch {src_str} without intervention. "
        f"This is the recommended action for low-severity alerts — "
        f"continue observing to determine if the pattern escalates.\n\n"
        f"✕  IGNORE: Dismiss. Appropriate if the flow matches known "
        f"background traffic or a routine network task."
    )



"""  Internal formatting helpers
Build the bulleted list of feature deviations shown at the bottom of
every explanation, regardless of which pattern matched.
Format per line:
  - [feature label]: [value] ([X.Xσ above/below baseline])
"""
def _build_feature_breakdown(top_devs: list[FeatureDeviation]) -> list[str]:
    lines = []
    for dev in top_devs:
        direction = dev.direction
        z_abs = abs(dev.z_score)

        # Choose intensity word based on Z-score magnitude
        if z_abs >= 4.0:
            intensity = "extremely"
        elif z_abs >= 2.5:
            intensity = "significantly"
        elif z_abs >= 1.5:
            intensity = "notably"
        else:
            intensity = "slightly"

        val_str = _fmt_val(dev.flow_value)

        # For packet_rate and bytes, add the multiplier for extra context
        mult_str = ""
        if dev.baseline_mean > 0 and dev.multiplier >= 2.0:
            mult_str = f", {dev.multiplier:.1f}× the baseline"

        lines.append(
            f"  • {dev.label}: {val_str} "
            f"({intensity} {direction} baseline, Z={dev.z_score:+.2f}{mult_str})"
        )

    return lines

"""
Build a generic explanation when no specific attack pattern matched.
Describes the top features without guessing attack type.
"""
def _feature_fallback(
    top_devs: list[FeatureDeviation],
    protocol: str,
    dst_port: int,
) -> str:

    if not top_devs:
        return (
            "The Isolation Forest model flagged this flow as anomalous, "
            "but no specific indicators are available. "
            "Review the raw flow values above for context."
        )

    proto_str = protocol.upper() if protocol else "network"
    port_str  = _port_label(dst_port) if dst_port > 0 else ""

    # Pick the most deviant feature and describe it specifically
    top = top_devs[0]
    direction = top.direction
    z_abs = abs(top.z_score)

    if z_abs >= 3.0:
        degree = "dramatically"
    elif z_abs >= 2.0:
        degree = "significantly"
    else:
        degree = "noticeably"

    lead = (
        f"The Isolation Forest model found this {proto_str} flow statistically "
        f"unusual. The most significant indicator was {top.label.lower()}, "
        f"which was {degree} {direction} the learned baseline "
        f"(Z={top.z_score:+.2f})."
    )

    # Add port context if relevant
    if port_str:
        lead += f" The flow targeted {port_str}."

    # If there are multiple deviating features, add a connector sentence
    if len(top_devs) >= 2:
        second = top_devs[1]
        lead += (
            f" Additionally, {second.label.lower()} was "
            f"{second.direction} baseline by {abs(second.z_score):.1f} standard deviations."
        )

    return lead




"""  Standalone formatting utility used by dashboard and CLI report
Format an Alert as a multi-section CLI report for the terminal.
Designed for the `python3 cli.py hitl` command's output; gives the
user a clear, readable summary without needing the web dashboard.
Parameters
alert : Alert
  A fully-constructed Alert object from hitl.py.
Returns str
  Formatted multi-line string ready to print to stdout.
"""
def format_alert_for_cli(alert) -> str:
    SEP  = "─" * 60
    SEP2 = "═" * 60

    sev_colour = {
        Severity.HIGH: "\033[91m",  # red
        Severity.MEDIUM: "\033[93m",  # yellow
        Severity.LOW: "\033[94m",  # blue
    }.get(alert.severity, "")
    RESET = "\033[0m"

    lines = [
        SEP2,
        f"{sev_colour}ALERT {alert.alert_id}  |  {alert.severity.value.upper()}  |  "
        f"confidence {alert.confidence_pct:.0f}%{RESET}",
        SEP2,
        f"  Source : {alert.src_ip}:{alert.src_port}",
        f"  Destination : {alert.dst_ip}:{alert.dst_port}",
        f"  Protocol : {alert.protocol.upper() if alert.protocol else 'unknown'}",
        f"  Flow stats : {alert.bytes:,} bytes | {alert.packets:,} packets "
        f"| {alert.duration:.4f}s",
        f"  Score : {alert.anomaly_score:.4f}  (rank {alert.anomaly_rank}/{alert.batch_size})",
        SEP,
        "EXPLANATION",
        SEP,
        alert.explanation,
        SEP,
        "RECOMMENDATION",
        SEP,
        alert.recommendation,
        SEP2,
        f"Decision: [{alert.decision.value.upper()}]",
        SEP2,
    ]

    return "\n".join(lines)

"""
Single-line summary of an alert for use in the CLI listing view when multiple alerts are displayed together.
Example:
  [a1b2c3d4] HIGH   95%  192.168.1.50 → 10.0.0.1:80   Potential DDoS
"""
def format_alert_summary_line(alert) -> str:
    sev_label = f"{'HIGH' if alert.severity == Severity.HIGH else alert.severity.value.upper():<6}"

    # Extract the detection pattern name from the first line of the explanation
    # (format: "Detection: <pattern name>")
    pattern = "anomaly detected"
    for line in alert.explanation.splitlines():
        if line.startswith("Detection:"):
            pattern = line.replace("Detection:", "").strip()
            break

    return (
        f"[{alert.alert_id}] {sev_label} {alert.confidence_pct:>5.1f}%  "
        f"{alert.src_ip}:{alert.src_port} → "
        f"{alert.dst_ip}:{alert.dst_port}   "
        f"{pattern}"
    )
