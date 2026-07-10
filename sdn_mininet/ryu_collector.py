from __future__ import annotations
import eventlet
eventlet.monkey_patch()

#!/usr/bin/env python3
"""
sdn_mininet/ryu_collector.py: Ryu SDN Controller + Flow Stats Collector with Byzantine
Robust Model Poisoning Defense + HITL Alert Endpoint. This Ryu app does four main jobs:
1. Acts as a basic learning L2 switch so hosts in Mininet can ping each other
2. Periodically collects OpenFlow flow statistics from all switches and saves them as 
CSV files for our anomaly detection tool.
3. Exposes REST endpoints for FL clients to upload local model metrics and triggers 
sanitized aggregation to defend against model poisoning attacks.
4. Exposes HITL REST endpoints so external scripts can push anomaly alerts
directly into a Ryu-side queue.
The collected data is written to:
data/live_client1.csv (switch s1 / dpid=1)
data/live_client2.csv (switch s2 / dpid=2)
data/live_client3.csv (switch s3 / dpid=3)
REST API (all on port 8080):
POST /fl/upload -> client pushes local model metric (Tool 2)
GET /fl/aggregate -> trigger sanitized aggregation (Tool 2)
GET /fl/status -> query current global model state (Tool 2)
GET /fl/reset -> clear upload queue for next FL round (Tool 2)
POST /hitl/alert -> push a detected anomaly to the HITL queue (Tool 4)
GET /hitl/status -> return HITL queue size and last alert time (Tool 4)
Note on Tool 4 integration: The dashboard (dashboard/app.py) does NOT depend on /hitl/alert. 
It reads live_client*.csv directly via its background auto-scanner. The /hitl/* endpoints 
are an optional path for custom scripts that want to surface alerts through the Ryu REST layer.
Usage (run from project root):
ryu-manager sdn_mininet/ryu_collector.py --observe-links
"""
import csv
import json
import os
import sys
import threading
import time
from collections import defaultdict
from typing import Dict, List, Optional
# Add project root to path so src/ is importable from where ryu-manager is invoked from.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ethernet, ipv4, ipv6, packet, tcp, udp, icmp, arp
from ryu.ofproto import ofproto_v1_3
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response
# Tool 2: import sanitizer
from src.sanitizer import aggregate_with_sanitizer, SanitizationReport
from src.features import load_flows # available for live scoring

# Configuration
POLL_INTERVAL = 5 # How often to poll switches for flow stats (in seconds)
OUTPUT_DIR = "data" # Where to save the live CSV files
MAX_ROWS = 5000 # Future: rotate files after this many rows

# Map switch DPID to client CSV name
DPID_TO_CLIENT = {
    1: "live_client1",
    2: "live_client2",
    3: "live_client3",
}

# Columns written to every live CSV
CSV_FIELDNAMES = [
    "timestamp", "dpid",
    "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "bytes", "packets", "duration", "flags", "label",
]

# Tool 2: REST API configuration
REST_APP_NAME = "fl_sanitizer_api"
Z_THRESHOLD = float(os.environ.get("Z_THRESHOLD", "1.5"))
SANITIZER_LOG_PATH = os.environ.get("SANITIZER_LOG_PATH", "results/ryu_sanitizer.log")

# Tool 4: HITL queue configuration
# Maximum number of alert dicts held in memory.
# Oldest entry is deleted when the cap is hit.
HITL_QUEUE_MAX = int(os.environ.get("HITL_QUEUE_MAX", "100"))

# Module-level state
# Tool 2: in-memory FL upload queue (cleared each FL round)
_upload_queue: Dict[str, float] = {}
_last_global_model: Optional[float] = None
_last_report: Optional[SanitizationReport] = None

# Tool 4: HITL alert queue and thread lock
# The lock protects concurrent access from Ryu's WSGI thread (handling /hitl/alert POST) 
# and any reader of the queue. I use threading.Lock rather than Ryu's hub primitives 
# because the lock is held for microseconds.
_hitl_alert_queue: List[dict] = []
_hitl_last_alert_at: Optional[float] = None
_hitl_lock = threading.Lock()

# Main Ryu Application
class SDNSanitizerController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Tool 1: switch learning and monitoring state
        self.mac_to_port = {} # MAC address learning table per switch
        self.datapaths = {} # Connected switches
        self._writers = {} # CSV DictWriter objects
        self._files = {} # Open file handles
        self._row_counts = defaultdict(int) # Rows written per client
        # IP-layer cache: (dpid, src_mac, dst_mac) -> {src_ip, dst_ip, protocol, dst_port, src_port}
        # Populated by packet_in_handler so _stat_to_row can write real IPs and ports
        # instead of MAC addresses and zeros.
        self._flow_ip_cache: Dict[tuple, dict] = {}
        # MAC -> IP mapping built opportunistically from ARP and IPv4 packet-in payloads.
        # Used by _stat_to_row as a fallback when _flow_ip_cache has no entry.
        self.mac_to_ip: Dict[str, str] = {}
        # Tool 2: register REST API handler
        wsgi = kwargs["wsgi"]
        wsgi.register(FLSanitizerAPI, {REST_APP_NAME: self})
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        os.makedirs("results", exist_ok=True)
        # Start background thread that polls switches every POLL_INTERVAL seconds
        self.monitor_thread = hub.spawn(self._monitor_loop)
        self.logger.info("[Ryu] SDN Sanitizer Controller started!")
        self.logger.info(f" Polling every {POLL_INTERVAL} seconds -> {OUTPUT_DIR}/")
        self.logger.info(f"[Ryu] Zero-trust FL aggregation active — Z threshold: {Z_THRESHOLD}")
        # Tool 4: log the new HITL endpoints so the operator sees them at startup
        self.logger.info("[Ryu] Tool 4 HITL endpoints active:")
        self.logger.info("[Ryu] POST http://127.0.0.1:8080/hitl/alert -> push anomaly alert")
        self.logger.info("[Ryu] GET http://127.0.0.1:8080/hitl/status -> HITL queue status")

    # OpenFlow event handlers
    # Called when a switch connects to the controller
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath
        self.logger.info(f"[Ryu] Switch {datapath.id} connected — table-miss flow installed")
        # Install table-miss flow: send unknown packets to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, priority=0, match=match, actions=actions, idle_timeout=0, hard_timeout=0)
       
        # Force the switch to send full packet data (not truncated) on packet-in events. 
        # Some patch-port/bridge configurations leave miss_send_len at 0, which causes 
        # packet_in_handler to receive empty msg.data and silently drop the packet.
        req = parser.OFPSetConfig(
            datapath,
            ofproto.OFPC_FRAG_NORMAL,
            ofproto.OFPCML_NO_BUFFER
        )
        datapath.send_msg(req)

    # Packet-In Handler (Learning Switch)
    # Handle packet-in messages and learn MAC addresses
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if eth_pkt is None:
            return
        dst_mac = eth_pkt.dst
        src_mac = eth_pkt.src
        dpid = datapath.id

        # Cache IP-layer information for this flow. July 10 change.******* update
        # Every first packet passes through packet_in before a forwarding rule is installed.
        # We extract IP/TCP/UDP headers here so _stat_to_row can write real IPs and ports.
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)

        if ip_pkt:
            if tcp_pkt:
                proto = "tcp"
                dst_port = tcp_pkt.dst_port
                src_port = tcp_pkt.src_port
            elif udp_pkt:
                proto = "udp"
                dst_port = udp_pkt.dst_port
                src_port = udp_pkt.src_port
            elif icmp_pkt:
                proto = "icmp"
                dst_port = 0
                src_port = 0
            else:
                proto = "ipv4"
                dst_port = 0
                src_port = in_port

            self._flow_ip_cache[(dpid, src_mac, dst_mac)] = {
                "src_ip": ip_pkt.src,
                "dst_ip": ip_pkt.dst,
                "protocol": proto,
                "dst_port": dst_port,
                "src_port": src_port,
            }

        # Learn MAC -> IP opportunistically from packet-in payloads.
        # This allows flow CSVs and dashboard alerts to show IPv4 addresses
        # while preserving MAC fallback for non-IP traffic.
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt and arp_pkt.src_ip:
            self.mac_to_ip[src_mac] = arp_pkt.src_ip
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt and ipv4_pkt.src:
            self.mac_to_ip[src_mac] = ipv4_pkt.src
            if ipv4_pkt.dst and dst_mac and dst_mac != "ff:ff:ff:ff:ff:ff":
                # Best-effort reverse mapping for destination host when known.
                self.mac_to_ip.setdefault(dst_mac, ipv4_pkt.dst)

        # Learn the source MAC -> port mapping
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port
        # Decide output port
        out_port = self.mac_to_port[dpid].get(dst_mac) or ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]
        # Install a forwarding rule if we know the destination
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port,
                                    eth_dst=dst_mac,
                                    eth_src=src_mac)
            self._add_flow(datapath, priority=1, match=match, actions=actions)
        # Send the packet out
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data,
        )
        datapath.send_msg(out)

    # Process flow statistics received from switches
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        datapath = ev.msg.datapath
        dpid = datapath.id
        client = DPID_TO_CLIENT.get(dpid, f"live_client{dpid}")
        writer = self._get_writer(client)
        ts = time.strftime("%Y-%m-%dT%H:%M:%S")
        rows_written = 0
        for stat in body:
            row = self._stat_to_row(stat, dpid, ts)
            if row:
                writer.writerow(row)
                rows_written += 1
                self._row_counts[client] += 1
        if rows_written:
            self._files[client].flush()
            self.logger.info(
                f"[Collector] dpid={dpid} ({client}): "
                f"+{rows_written} flows (total={self._row_counts[client]})"
            )

    # Background monitoring
    # Background thread: poll switches for flow stats periodically
    def _monitor_loop(self):
        while True:
            hub.sleep(POLL_INTERVAL)
            for datapath in list(self.datapaths.values()):
                try:
                    self._request_flow_stats(datapath)
                except Exception:
                    # A bad/disconnected datapath should not silently kill the whole polling loop. 
                    # Log it and keep going so the other switches keep collecting data.
                    self.logger.exception(
                        f"[Collector] Failed to request flow stats for dpid={datapath.id}"
                    )
   
    # Send a flow stats request to a switch
    def _request_flow_stats(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        req = parser.OFPFlowStatsRequest(
            datapath,
            flags = 0,
            table_id = ofproto.OFPTT_ALL,
            out_port = ofproto.OFPP_ANY,
            out_group = ofproto.OFPG_ANY,
            cookie = 0,
            cookie_mask = 0,
        )
        datapath.send_msg(req)

    # Helper functions
    # Install a flow entry on the switch
    def _add_flow(self, datapath, priority, match, actions,
                  idle_timeout=30, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath = datapath,
            priority = priority,
            match = match,
            instructions = inst,
            idle_timeout = idle_timeout,
            hard_timeout = hard_timeout,
        )
        datapath.send_msg(mod)

    # Convert an OpenFlow flow stat entry into a CSV row dict.
    # Looks up the IP-layer cache populated by packet_in_handler so the row
    # contains real IPv4 addresses, protocol names, and port numbers rather
    # than MAC addresses and zeros. Falls back to mac_to_ip ARP table, then
    # raw MAC address for pure L2 traffic.
    def _stat_to_row(self, stat, dpid, ts) -> dict:
        match = stat.match
        src_mac = match.get("eth_src", "")
        dst_mac = match.get("eth_dst", "")
        # Skip table-miss entries (they have no src/dst)
        if not src_mac or not dst_mac:
            return None
        duration = stat.duration_sec + stat.duration_nsec / 1e9
        # Look up IP-layer info cached from packet_in
        cache = self._flow_ip_cache.get((dpid, src_mac, dst_mac), {})
        return {
            "timestamp": ts,
            "dpid": dpid,
            "src_ip": cache.get("src_ip",   self.mac_to_ip.get(src_mac, src_mac)),
            "dst_ip": cache.get("dst_ip",   self.mac_to_ip.get(dst_mac, dst_mac)),
            "src_port": cache.get("src_port", match.get("in_port", 0)),
            "dst_port": cache.get("dst_port", 0),
            "protocol": cache.get("protocol", "ethernet"),
            "bytes": stat.byte_count,
            "packets": stat.packet_count,
            "duration": round(duration, 6),
            "flags": "",
            "label": 0,
        }

    # Get or create a CSV writer for a specific client.
    # Appends to an existing file if it already exists.
    def _get_writer(self, client: str):
        if client not in self._writers:
            path = os.path.join(OUTPUT_DIR, f"{client}.csv")
            file_exists = os.path.isfile(path)
            f = open(path, "a", newline="")
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
            if not file_exists:
                writer.writeheader()
            self._writers[client] = writer
            self._files[client] = f
            self.logger.info(f"[Collector] Opened/created CSV: {path}")
        return self._writers[client]

    # Tool 2: sanitizer trigger called by the /fl/aggregate REST endpoint.
    # Consumes the current upload queue, applies the Z-score sanitizer,
    # and updates the module-level global model state.
    def run_sanitized_aggregation(self, z_threshold: float = Z_THRESHOLD):
        global _last_global_model, _last_report
        if not _upload_queue:
            self.logger.warning("[Sanitizer] Aggregation triggered with empty queue")
            return None, None
        self.logger.info(
            "[Sanitizer] Aggregating %d hosts: %s",
            len(_upload_queue), list(_upload_queue.keys()),
        )
        global_model, report = aggregate_with_sanitizer(
            dict(_upload_queue), z_threshold=z_threshold
        )
        _last_global_model = global_model
        _last_report = report
        # Append sanitizer summary to the log file
        with open(SANITIZER_LOG_PATH, "a") as logf:
            ts = time.strftime("%Y-%m-%dT%H:%M:%S")
            for line in report.summary_lines():
                logf.write(f"[{ts}] {line}\n")
            if report.poisoning_detected:
                logf.write(
                    f"[{ts}] ALERT: Rejected hosts -> {report.rejected_hosts}\n"
                )
            logf.write("\n")
        return global_model, report


# REST API Handler (Tools 2 + 4)
# Ryu WSGI REST API handler. Implements the /fl/* endpoints (Tool 2) 
# and /hitl/* endpoints (Tool 4). All responses are JSON. 
# Ryu's WSGI layer runs this in a gevent greenlet,
# so standard Python threading.Lock is safe to use for _hitl_lock.
class FLSanitizerAPI(ControllerBase):
    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.controller: SDNSanitizerController = data[REST_APP_NAME]

    # Tool 2: FL endpoints
    # Client pushes its local model metric.
    # Body: {"host_id": "h1", "metric": 0.12}
    @route("fl", "/fl/upload", methods=["POST"])
    def upload_metric(self, req, **kwargs):
        try:
            body = json.loads(req.body)
            host_id = str(body["host_id"])
            metric = float(body["metric"])
        except (KeyError, ValueError, json.JSONDecodeError) as exc:
            return Response(
                status=400,
                content_type="application/json",
                charset="utf-8",
                body=json.dumps({"error": str(exc)}),
            )
        _upload_queue[host_id] = metric
        return Response(
            content_type="application/json",
            charset="utf-8",
            body=json.dumps({
                "status": "queued",
                "host_id": host_id,
                "queue_size": len(_upload_queue),
            }),
        )
    
    # Trigger sanitized aggregation over all queued uploads
    @route("fl", "/fl/aggregate", methods=["GET"])
    def trigger_aggregation(self, req, **kwargs):
        global_model, report = self.controller.run_sanitized_aggregation()
        if report is None:
            return Response(
                status=400,
                content_type="application/json",
                charset="utf-8",
                body=json.dumps({"error": "Upload queue is empty"}),
            )
        result = {
            "global_model": global_model,
            "accepted": report.accepted_hosts,
            "rejected": report.rejected_hosts,
            "poisoning_detected": report.poisoning_detected,
            "n_submitted": report.n_submitted,
        }
        return Response(
            content_type="application/json",
            charset="utf-8",
            body=json.dumps(result),
        )

    # Return current upload queue and last known global model
    @route("fl", "/fl/status", methods=["GET"])
    def get_status(self, req, **kwargs):
        return Response(
            content_type="application/json",
            charset="utf-8",
            body=json.dumps({
                "queued_hosts": list(_upload_queue.keys()),
                "queue_size": len(_upload_queue),
                "last_global_model": _last_global_model,
                "poisoning_detected_last_round": (
                    _last_report.poisoning_detected if _last_report else None
                ),
            }),
        )

    # Clear the upload queue to start a new FL round
    @route("fl", "/fl/reset", methods=["GET"])
    def reset_queue(self, req, **kwargs):
        _upload_queue.clear()
        return Response(
            content_type="application/json",
            charset="utf-8",
            body=json.dumps({"status": "queue cleared"}),
        )

    
    """ # Tool 4: HITL endpoints
    Tool 4: Push a detected anomaly into the Ryu-side HITL alert queue.
    Called by external scripts that want to surface an alert to the dashboard through 
    the Ryu REST layer rather than waiting for the dashboard's auto-scanner to pick 
    it up from the live CSV. The dashboard does NOT depend on this endpoint for its 
    core loop. It reads live_client*.csv directly. This is an optional fast-path for 
    custom integrations. Request body (JSON) with defaults applied:
       {
         "src_ip": "10.0.0.4",
         "dst_ip": "10.0.0.1",
         "src_port": 12345,
         "dst_port": 80,
         "protocol": "tcp",
         "bytes": 1500000,
         "packets": 5000,
         "duration": 0.12,
         "anomaly_score": -0.45,
         "dpid": 2
       }
     Response:
       { "status": "queued", "queue_size": N, "received_at": "..." }
     """
    @route("hitl", "/hitl/alert", methods=["POST"])
    def push_hitl_alert(self, req, **kwargs):
        try:
            body = json.loads(req.body)
        except (ValueError, json.JSONDecodeError) as exc:
            return Response(
                status=400,
                content_type="application/json",
                charset="utf-8",
                body=json.dumps({"error": str(exc)}),
            )
        now = time.time()
        alert = {
            "src_ip": str(body.get("src_ip", "unknown")),
            "dst_ip": str(body.get("dst_ip", "unknown")),
            "src_port": int(body.get("src_port", 0)),
            "dst_port": int(body.get("dst_port", 0)),
            "protocol": str(body.get("protocol", "unknown")),
            "bytes": int(body.get("bytes", 0)),
            "packets": int(body.get("packets", 0)),
            "duration": float(body.get("duration", 0.0)),
            "anomaly_score": float(body.get("anomaly_score", 0.0)),
            "dpid": int(body.get("dpid", 0)),
            "received_at": now,
            "received_at_str": time.strftime("%Y-%m-%dT%H:%M:%S",
                                             time.localtime(now)),
        }
        with _hitl_lock:
            _hitl_alert_queue.append(alert)
            # Evict oldest entry when the queue is full
            if len(_hitl_alert_queue) > HITL_QUEUE_MAX:
                _hitl_alert_queue.pop(0)
            global _hitl_last_alert_at
            _hitl_last_alert_at = now
            queue_size = len(_hitl_alert_queue)
        self.controller.logger.info(
            "[HITL] Alert queued: src=%s dst=%s:%d score=%.4f (queue=%d)",
            alert["src_ip"], alert["dst_ip"], alert["dst_port"],
            alert["anomaly_score"], queue_size,
        )
        return Response(
            content_type="application/json",
            charset="utf-8",
            body=json.dumps({
                "status": "queued",
                "queue_size": queue_size,
                "received_at": alert["received_at_str"],
            }),
        )


    """
    Tool 4: Return current HITL alert queue size and last alert time.
    Called by the dashboard's /api/health endpoint to show whether the Ryu-side queue 
    has unread alerts. The last 5 alert summaries are included for a lightweight 
    preview without needing a separate fetch.
    Response:
    {
        "hitl_queue_size": N,
        "last_alert_at": <unix timestamp or null>,
        "last_alert_at_str": "2026-05-29T14:30:00" or null,
        "recent_alerts": [ ... last 5 alert dicts ... ]
    }
    """
    @route("hitl", "/hitl/status", methods=["GET"])
    def hitl_status(self, req, **kwargs):
        with _hitl_lock:
            queue_size = len(_hitl_alert_queue)
            last_alert = _hitl_last_alert_at
            recent_alerts = list(_hitl_alert_queue[-5:]) # snapshot, not a reference
        return Response(
            content_type="application/json",
            charset="utf-8",
            body=json.dumps({
                "hitl_queue_size": queue_size,
                "last_alert_at": last_alert,
                "last_alert_at_str": (
                    time.strftime("%Y-%m-%dT%H:%M:%S",
                                  time.localtime(last_alert))
                    if last_alert else None
                ),
                "recent_alerts": recent_alerts,
            }),
        )
