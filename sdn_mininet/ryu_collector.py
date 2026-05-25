""" sdn_mininet/ryu_collector.py
Tool 2, runs in the Ryu Controller, intercepts data, validates via Z-score, then aggregates.

This is an extension of Tool 1.
It adds the REST endpoints so that Mininet hosts can upload their metrics to the controller.
- REST endpoint: POST /fl/upload  (clients push local model metrics)
- REST endpoint: GET  /fl/status  (query current global model state)
- Calls src.sanitizer.aggregate_with_sanitizer() before running FedAvg
- Logs all poisoning alerts to ryu_sanitizer.log
- Treats all incoming model updates as untrusted until statistically verified

Usage: ryu-manager sdn_mininet/ryu_collector.py --observe-links

REST API (runs on port 8080):
- Upload client's model update to Ryu controller
POST /fl/upload
    Body: {"host_id": "h1", "metric": 0.12}
    Response: {"status": "queued", "host_id": "h1"}

- get all uploaded model metrics and sanitize them, then calc FedAvg
GET /fl/aggregate
    Triggers sanitized aggregation over all queued uploads.
    Response: {"global_model": 0.13, "accepted": [...], "rejected": [...]}

- get clients that submitted data that has not yet been processed
GET /fl/status
    Response: {"queued_hosts": [...], "last_global_model": 0.13}

- clear the queue
GET /fl/reset
    Clears the upload queue for the next FL round.
"""

from __future__ import annotations

import json
import logging
import os
import csv
from datetime import datetime
from typing import Dict, Optional

# Ryu imports — only available inside the Mininet/Ryu environment
try:
    from ryu.base import app_manager
    from ryu.controller import ofp_event
    from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
    from ryu.ofproto import ofproto_v1_3
    from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
    from ryu.app.wsgi import ControllerBase, WSGIApplication, route
    from webob import Response
    RYU_AVAILABLE = True
except ImportError:
    # Allow module to be imported and tested outside the Ryu environment
    RYU_AVAILABLE = False
    app_manager = None
    ControllerBase = object

# from Tool 2's sanitizer, retrieve function and report
from src.sanitizer import aggregate_with_sanitizer, SanitizationReport

# from features.py, load extraction function that transforms raw data into ML features
# for anamoly detection
from src.features import extract_features  # noqa: F401 - available for live scoring

logger = logging.getLogger(__name__)

# Configuration settings
FLOW_LOG_PATH = os.environ.get("FLOW_LOG_PATH", "data/live_flows.csv")  # store stats
SANITIZER_LOG_PATH = os.environ.get("SANITIZER_LOG_PATH", "results/ryu_sanitizer.log") # stores suspicious updates
Z_THRESHOLD = float(os.environ.get("Z_THRESHOLD", "1.5"))  # define the statistical Z-score threshold
REST_APP_NAME = "fl_sanitizer_api"  # name of the REST API app running in SDN controller

# In-memory upload queue for temporary storage
_upload_queue: Dict[str, float] = {}
_last_global_model: Optional[float] = None
_last_report: Optional[SanitizationReport] = None



'''Ryu Controller App
  1. Collects OpenFlow flow stats and store in a CSV file
  2. Provide REST endpoints for FL clients to upload local model metrics via HTTP requests
  3. Applies Byzantine Z-score sanitizer before FedAvg
'''
# make sure controller is installed and running
if RYU_AVAILABLE:
    class SDNSanitizerController(app_manager.RyuApp):  # create SDN controller app
        OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]   # use OpenFlow 1.3
        _CONTEXTS = {"wsgi": WSGIApplication}   # enable web server functions

        # constructor for SDNSanitizerController class
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            wsgi = kwargs["wsgi"]
            wsgi.register(FLSanitizerAPI, {REST_APP_NAME: self})

            os.makedirs("data", exist_ok=True)  # store files and logs
            os.makedirs("results", exist_ok=True)  # for sanitizer logs, reports, and aggregation results

            # Initialize the CSV file to store flow stats collected by SDN Controller
            if not os.path.exists(FLOW_LOG_PATH):
                with open(FLOW_LOG_PATH, "w", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow([  # header row
                        "timestamp", "datapath_id", "in_port", "eth_dst", "eth_src",
                        "ip_src", "ip_dst", "ip_proto", "tp_src", "tp_dst",
                        "byte_count", "packet_count", "duration_sec",
                    ])
            logger.info("[Ryu] SDN Sanitizer Controller started")
            logger.info("[Ryu] Zero-trust FL aggregation active — Z threshold: %.1f", Z_THRESHOLD)

        ''' see 6 lines above
        ---Header---	---Meaning---
        timestamp	    Time the flow was recorded
        datapath_id	    Unique ID of the OpenFlow switch
        in_port	        Switch port where traffic entered
        eth_dst	        Destination MAC address
        eth_src	        Source MAC address
        ip_src	        Source IP address
        ip_dst	        Destination IP address
        ip_proto	    IP protocol (TCP, UDP, ICMP, etc.)
        tp_src	        Source transport-layer port
        tp_dst	        Destination transport-layer port
        byte_count	    Total bytes transferred
        packet_count    Total packets transferred
        duration_sec	Length of the flow in seconds
        '''

        # Install table-miss flow entry on switch connect to Ryu Controller
        @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
        def switch_features_handler(self, ev):
            datapath = ev.msg.datapath  # retrieve switch object
            ofproto = datapath.ofproto  # load OpenFlow protocol constants and definitions
            parser = datapath.ofproto_parser  # load helper functions for OpenFlow messages and rules
            match = parser.OFPMatch()  # match packets that do not match any rules
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)] # unmatched packets
            self._add_flow(datapath, 0, match, actions)  # install rule into switch
            logger.info("[Ryu] Switch %s connected — table-miss flow installed", datapath.id)


        '''Helper function to install a flow rule on a datapath
        Allows controller to add a new rule
        datapath: connected switch
        priority: importance of the rule
        match: traffic conditions to mach
        actions: what the switch should do with matching traffic
        idle_timeout: remove rule if unused 
        hard_timeout: remove rule after fixed time
        '''
        def _add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                instructions=inst,
                idle_timeout=idle_timeout,
                hard_timeout=hard_timeout,
            )
            datapath.send_msg(mod)

        """
        Receive flow stats from switches and logs to CSV.
        Starts upon receiving a FlowStatsReply message from a switch
        """
        @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
        def flow_stats_reply_handler(self, ev):
            body = ev.msg.body  # extracts the list of flow entries sent by switch
            dp_id = ev.msg.datapath.id  # get id of switch
            ts = datetime.utcnow().isoformat()  # create a timestamp
            with open(FLOW_LOG_PATH, "a", newline="") as f:  # open flow log
                writer = csv.writer(f)
                for stat in body:
                    writer.writerow([
                        ts, dp_id,
                        stat.match.get("in_port", ""),
                        stat.match.get("eth_dst", ""),
                        stat.match.get("eth_src", ""),
                        stat.match.get("ipv4_src", ""),
                        stat.match.get("ipv4_dst", ""),
                        stat.match.get("ip_proto", ""),
                        stat.match.get("tcp_src", stat.match.get("udp_src", "")),
                        stat.match.get("tcp_dst", stat.match.get("udp_dst", "")),
                        stat.byte_count,
                        stat.packet_count,
                        stat.duration_sec,
                    ])

                    '''
                    ---Field---	    ---Meaning---
                    ts	            Time the stats were recorded
                    dp_id	        Switch ID
                    in_port	        Input port of traffic
                    eth_dst	        Destination MAC
                    eth_src	        Source MAC
                    ipv4_src    	Source IP
                    ipv4_dst	    Destination IP
                    ip_proto	    Protocol (TCP/UDP/etc.)
                    tcp_src/udp_src	Source transport port
                    tcp_dst/udp_dst	Destination transport port
                    byte_count	    Total bytes transferred
                    packet_count	Total packets
                    duration_sec	How long the flow existed
                    '''


        """ Sanitizer trigger (called by REST API)
        This is where FL aggregation occurs after filtering malicious data
        1. Takes all uploaded client updates stored in _upload_queue
        2. Runs a Z-score based sanitizer to detect outliers (possible attacks)
        3. Aggregates only the “safe” updates into a new global model
        4. Stores the result for later use via REST API
        Returns: (global_model, SanitizationReport)
        """
        def run_sanitized_aggregation(self, z_threshold: float = Z_THRESHOLD):
            global _last_global_model, _last_report

            if not _upload_queue:  # if no clients submitted data
                logger.warning("[Sanitizer] Aggregation triggered with empty queue")
                return None, None

            logger.info(  # number of hosts participants and their IDs
                "[Sanitizer] Aggregating %d hosts: %s",
                len(_upload_queue), list(_upload_queue.keys()),
            )

            # copies uploaded queue, applies Z-score anomaly detection, removes suspicious updates
            # performs FedAvg aggregation and returns global_model (new aggregated results) and
            # returns report of accepted/rejected clients
            global_model, report = aggregate_with_sanitizer(
                dict(_upload_queue), z_threshold=z_threshold
            )

            # store latest global model and sanitization report
            _last_global_model = global_model
            _last_report = report

            # Write to sanitizer alert log for persistence
            with open(SANITIZER_LOG_PATH, "a") as logf:
                ts = datetime.utcnow().isoformat()
                for line in report.summary_lines():
                    logf.write(f"[{ts}] {line}\n")
                if report.poisoning_detected:
                    logf.write(
                        f"\033[91m[{ts}] ALERT: Rejected hosts ->\033[0m {report.rejected_hosts}\n"
                    )
                logf.write("\n")

            return global_model, report


    """REST API Handler
    REST API/Ryu REST Controller: FL clients can upload local model metrics here and request
    sanitized aggregation. Opens HTTP endpoints for the FL system.
    """
    class FLSanitizerAPI(ControllerBase):
        '''Constructor
        req: the incomming HTTP request
        link: Ryu REST framework reference
        data: data passed from controller
        **config: configuration options from Ryu
        '''
        def __init__(self, req, link, data, **config):
            super().__init__(req, link, data, **config)
            self.controller: SDNSanitizerController = data[REST_APP_NAME]

        '''
        Function makes a REST API endpoint that lets clients send their local FL metric to
        the SDN controller. URL: /fl/upload, method: POST
        '''
        @route("fl", "/fl/upload", methods=["POST"])
        def upload_metric(self, req, **kwargs):
            try:
                body = json.loads(req.body)
                host_id = str(body["host_id"])  # id switch that is sending data
                metric = float(body["metric"])  # local ML model stats
            except (KeyError, ValueError, json.JSONDecodeError) as exc:
                return Response(
                    status=400,
                    content_type="application/json",
                    body=json.dumps({"error": str(exc)}),
                )

            _upload_queue[host_id] = metric
            logger.info("[FL Upload] host=%s metric=%.4f (queue size=%d)", host_id, metric, len(_upload_queue))

            return Response(
                content_type="application/json",
                body=json.dumps({"status": "queued", "host_id": host_id, "queue_size": len(_upload_queue)}),
            )


        """ 
        This function defines a REST API endpoint that triggers FL aggregation after sanitization
        of all queued uploads. When you call GET /fl/aggregate, the controller will:
        1. Take all uploaded client metrics
        2. Run Z-score based sanitizer to detect outliers (possible attacks)
        3. Filter out the suspicious hosts
        4. Compute the new global model (or the FedAvg result)
        """
        @route("fl", "/fl/aggregate", methods=["GET"])
        def trigger_aggregation(self, req, **kwargs):
            global_model, report = self.controller.run_sanitized_aggregation()
            if report is None:
                return Response(
                    status=400,
                    content_type="application/json",
                    body=json.dumps({"error": "Upload queue is empty"}),
                )
            result = {
                "global_model": global_model,  # Final aggregated value after FedAvg
                "accepted": report.accepted_hosts,
                "rejected": report.rejected_hosts,
                "poisoning_detected": report.poisoning_detected,  # true if there is an attack
                "n_submitted": report.n_submitted,
            }
            return Response(
                content_type="application/json",
                body=json.dumps(result),
            )

        """Return current queue and last known global model.
        This function defines a REST API endpoint for monitoring the current state of the FL system.
        which clients have submitted data; how much data is waiting; the last computed global model;
        if an attack was detected in the last round
        """
        @route("fl", "/fl/status", methods=["GET"])
        def get_status(self, req, **kwargs):
            return Response(
                content_type="application/json",
                body=json.dumps({
                    "queued_hosts": list(_upload_queue.keys()),
                    "queue_size": len(_upload_queue),
                    "last_global_model": _last_global_model,
                    "poisoning_detected_last_round": (
                        _last_report.poisoning_detected if _last_report else None
                    ),
                }),
            )

        """Clear the upload queue to start a new FL round.
        This function defines a REST API endpoint that resets the FL round by clearing collected client updates.
        """
        @route("fl", "/fl/reset", methods=["GET"])
        def reset_queue(self, req, **kwargs):
            _upload_queue.clear()
            logger.info("[FL] Upload queue reset for new round")
            return Response(
                content_type="application/json",
                body=json.dumps({"status": "queue cleared"}),
            )


else:
    # Stub controller when Ryu/Mininet (SDN) environment is not available
    class SDNSanitizerController:  # type: ignore - don't have to check this class

        # simple aggregation function for stub controller - used for unit testing
        def run_sanitized_aggregation(self, z_threshold=Z_THRESHOLD):
            return aggregate_with_sanitizer(dict(_upload_queue), z_threshold=z_threshold)
           
