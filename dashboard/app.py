from __future__ import annotations
#!/usr/bin/env python3

""" dashboard/app.py
Tool 4: HITL Operator Dashboard Server
This Flask application is the Human-in-the-Loop (HITL) web interface for Tool 4.
It is connects the anomaly detection pipeline to the operator, i.e.,
detect.py feeds to hitl.py (AlertQueue) feeds to  app.py (REST API) sends to  dashboard UI
The human operator approves and mitigator.py sends to OVS switch.
The server runs on port 5000 (Ryu's uses port 8080) so both
can run at the same time without conflict.

REST API endpoints:
GET / -> Serve the operator dashboard HTML page
GET /api/alerts -> Return all alerts (pending + resolved)
GET /api/alerts/pending -> Return only PENDING alerts
GET /api/alerts/<id> -> Return one alert by ID
POST /api/decide -> Submit an operator decision for an alert
GET /api/stats -> Return queue summary counts
GET /api/mitigation/log -> Return the mitigation audit log
GET /api/mitigation/verify -> Run ovs-ofctl to verify installed rules
POST /api/scan -> Trigger a fresh detect() run on a data file
GET /api/health -> Health check, returns uptime and queue size

CORS is enabled so the dashboard HTML, served from /mnt/user-data or opened
as a local file, can call the API without browser cross-origin errors.
Usage:
# Start the dashboard (from project root):
python3 cli.py dashboard --model models/global.pkl --data data/new_flows.csv
# Or directly:
python3 dashboard/app.py --model models/global.pkl --data data/new_flows.csv
# Then open --> http://localhost:5000
"""

import argparse
import json
import logging
import os
import sys
import time
import threading
from typing import Optional

# Add project root to sys.path so src/ and sdn_mininet/ are importable
# whether app.py is run directly or via cli.py
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from flask import Flask, jsonify, request, send_from_directory, abort
from flask_cors import CORS

from src.hitl import AlertQueue, Alert, Decision, alerts_from_detections
from src.explainer import format_alert_for_cli
from sdn_mininet.mitigator import Mitigator, MitigationAction, verify_rule_installed

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("dashboard.app")

# Configuration
DASHBOARD_PORT = int(os.environ.get("DASHBOARD_PORT", "5000"))
DASHBOARD_HOST = os.environ.get("DASHBOARD_HOST", "0.0.0.0")
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")

# How often, in sec, the background scanner re-runs detect() on live data
AUTO_SCAN_INTERVAL = int(os.environ.get("AUTO_SCAN_INTERVAL", "30"))

# Minimum confidence to convert a detection into a dashboard alert
MIN_ALERT_CONFIDENCE = float(os.environ.get("MIN_ALERT_CONFIDENCE", "50.0"))

# Maximum alerts created per scan batch; prevents flooding under attack
MAX_ALERTS_PER_SCAN = int(os.environ.get("MAX_ALERTS_PER_SCAN", "20"))


"""  App factory
Create and configure the Flask application.
Parameters:
model_path: str
- Path to the trained model bundle (.pkl) used for detection.
- Passed at startup via CLI args or environment variable MODEL_PATH.
data_path: str
- Path to the flow CSV file to score. In live mode this is a live_client*.csv written by ryu_collector.py.
auto_scan : bool
If True, start a background thread that re-runs detect() every AUTO_SCAN_INTERVAL seconds, 
pushing new alerts automatically.  Returns:
Flask Configured app instance. Call app.run() or use gunicorn to serve.
"""
def create_app(
    model_path: str,
    data_path: str,
    auto_scan: bool = True,
) -> Flask:
    app = Flask(
        __name__,
        static_folder = STATIC_DIR,
        template_folder = TEMPLATES_DIR,
    )
    CORS(app)  # Allow calls from the HTML dashboard opened as a local file
    
    #Shared state
    # These objects are created once and shared across all requests. Flask is single-threaded 
    # by default in dev mode, but we use a lock for the scanner thread which runs concurrently.
    queue = AlertQueue(max_size=500)
    mitigator = Mitigator()
    start_time = time.time()

    # Store the most recent scan metadata for /api/health
    scan_meta: dict = {
        "last_scan_at": None,
        "last_scan_count": 0,
        "total_scans": 0,
        "model_path": model_path,
        "data_path": data_path,
    }
    scan_lock = threading.Lock()

    # Rows already scored, per data file, as of the previous scan. detect()
    # always scores the whole CSV (row scoring is independent per-row given
    # a pre-fit scaler, so this is correct). Without this,
    # every scan re-alerts on the same historical rows continuously. A stopped
    # attack continues to generate brand-new Alert objects because live_client*.csv
    # is append-only and nothing tracks which rows were already queued.
    # So, seed with the file's Current row count at startup rather than left
    # at 0; otherwise, restarting the dashboard (e.g. to flush the alert
    # queue for a clean demo) resets this to empty, and the very next scan
    # treats the Entire existing file as brand new, re-alerting on the
    # whole session's history at once. "Start clean" should mean "only
    # alert on what happens from now on," not "replay everything so far."
    _scanned_row_counts: dict[str, int] = {}
    if os.path.exists(data_path):
        try:
            import pandas as pd
            _scanned_row_counts[data_path] = len(pd.read_csv(data_path, low_memory=False))
            logger.info(
                "[Startup] %s already has %d row(s) — skipping to end, "
                "only new rows will generate alerts.",
                data_path, _scanned_row_counts[data_path],
            )
        except Exception as exc:
            logger.warning(
                "[Startup] Could not pre-count %s (%s) — will scan from the start.",
                data_path, exc,
            )

    
    """  Helper: run one detection scan
    Load the model, score the data file, convert anomalies to alerts,
    push them to the queue, and return the number of new alerts created.
    Safe to call from the background thread or from the /api/scan endpoint.
    """
    def run_scan(verbose: bool = False) -> int:
        try:
            import joblib
            from src.detect import detect
            if not os.path.exists(model_path):
                logger.warning("[Scan] Model not found: %s", model_path)
                return 0
            if not os.path.exists(data_path):
                logger.warning("[Scan] Data file not found: %s", data_path)
                return 0

            bundle = joblib.load(model_path)
            df = detect(model_path, data_path, verbose=verbose)

            # Only alert on rows appended since the last scan. Slice first,
            # then recompute anomaly_rank within just the new rows — the
            # rank/batch_size values detect() assigned are relative to the
            # WHOLE file, so passing them through unsliced would make
            # confidence_pct nonsensical once the file has more history
            # than one scan's worth of new rows.
            with scan_lock:
                already_scanned = _scanned_row_counts.get(data_path, 0)
                _scanned_row_counts[data_path] = len(df)

            new_rows_df = df.iloc[already_scanned:].copy()
            if not new_rows_df.empty:
                new_rows_df["anomaly_rank"] = (
                    new_rows_df["anomaly_score"].rank(ascending=True).astype(int)
                )

            new_alerts = alerts_from_detections(
                new_rows_df,
                bundle,
                min_confidence = MIN_ALERT_CONFIDENCE,
                max_alerts = MAX_ALERTS_PER_SCAN,
            )

            for alert in new_alerts:
                queue.push(alert)

            with scan_lock:
                scan_meta["last_scan_at"] = time.time()
                scan_meta["last_scan_count"] = len(new_alerts)
                scan_meta["total_scans"] += 1

            if new_alerts:
                logger.info(
                    "[Scan] Created %d new alert(s) from %d new flow(s) (pending queue: %d)",
                    len(new_alerts), len(new_rows_df), len(queue.pending()),
                )
            else:
                logger.debug("[Scan] No new alerts this cycle.")

            return len(new_alerts)

        except Exception as exc:
            logger.error("[Scan] Error during detection scan: %s", exc, exc_info=True)
            return 0

    """
    Background thread: re-run detect() periodically so the dashboard
    reflects fresh live_client*.csv data written by ryu_collector.py.
    """
    # Background auto-scanner
    def _scanner_loop():
        logger.info(
            "[AutoScan] Started, scanning every %ds. Model: %s | Data: %s",
            AUTO_SCAN_INTERVAL, model_path, data_path,
        )
        # Initial scan on startup
        run_scan(verbose=True)

        while True:
            time.sleep(AUTO_SCAN_INTERVAL)
            run_scan()

    if auto_scan:
        t = threading.Thread(target=_scanner_loop, daemon=True, name="hitl-scanner")
        t.start()

    # Routes
    # Dashboard HTML serve the operator dashboard HTML page.
    @app.route("/")
    def index():
        index_path = os.path.join(TEMPLATES_DIR, "index.html")
        if not os.path.exists(index_path):
            # show error if the template hasn't been created yet
            return (
                "<h2>Tool 4 Dashboard</h2>"
                "<p>dashboard/templates/index.html not found.<br>"
                "Run: <code>python3 cli.py dashboard --model models/global.pkl "
                "--data data/new_flows.csv</code></p>"
                "<p>API is running at <a href='/api/alerts'>/api/alerts</a></p>",
                200,
            )
        return send_from_directory(TEMPLATES_DIR, "index.html")
    # Serve JS, CSS, and other static assets.
    @app.route("/static/<path:filename>")
    def static_files(filename):
        return send_from_directory(STATIC_DIR, filename)

    
    """  Alert endpoints
    Return all alerts (pending and resolved), newest first.
    Query parameters:
      ?state=pending -> only PENDING alerts
      ?state=resolved -> only decided alerts
      ?limit=N -> return at most N alerts (default = 100)
    """  
    @app.route("/api/alerts", methods=["GET"])
    def get_all_alerts():
        state = request.args.get("state", "all")
        limit = int(request.args.get("limit", "100"))
        if state == "pending":
            alerts = queue.pending()
        elif state == "resolved":
            alerts = queue.resolved()
        else:
            alerts = queue.all_alerts()

        alerts = alerts[:limit]

        return jsonify({
            "alerts": [a.to_dict() for a in alerts],
            "count": len(alerts),
        })
    # Return only pending alerts; convenience shortcut for the dashboard poller
    @app.route("/api/alerts/pending", methods=["GET"])
    def get_pending_alerts():
        alerts = queue.pending()
        return jsonify({
            "alerts": [a.to_dict() for a in alerts],
            "count": len(alerts),
        })
    # Return a single alert by its 8-character ID
    @app.route("/api/alerts/<alert_id>", methods=["GET"])
    def get_alert(alert_id: str):
        alert = queue.get(alert_id)
        if alert is None:
            abort(404, description=f"Alert '{alert_id}' not found.")
        return jsonify(alert.to_dict())

    
    """  Decision endpoint
    Submit an operator decision for a pending alert.
    Request body (JSON):
      { "alert_id": "a1b2c3d4",
        "decision": "approved" | "monitor" | "ignored",
        "decided_by": "operator" (optional, default: "operator") }
    When decision == "approved", this endpoint also:
    1. Calls mitigator.from_alert() to install the DROP flow rule
    2. Returns the mitigation result alongside the updated alert
    Returns 200 with the updated alert dict on success.
    Returns 400 on bad input, 404 if alert not found, 409 if already decided.
    """
    @app.route("/api/decide", methods=["POST"])
    def submit_decision():
        body = request.get_json(silent=True)
        if not body:
            return jsonify({"error": "Request body must be JSON."}), 400

        alert_id = body.get("alert_id")
        decision_s = body.get("decision", "").strip().lower()
        decided_by = body.get("decided_by", "operator")

        if not alert_id:
            return jsonify({"error": "Missing field: alert_id"}), 400
        if not decision_s:
            return jsonify({"error": "Missing field: decision"}), 400

        # Map string to Decision enum
        decision_map = {
            "approved": Decision.APPROVED,
            "monitor": Decision.MONITOR,
            "ignored": Decision.IGNORED,
        }
        if decision_s not in decision_map:
            return jsonify({
                "error": f"Invalid decision '{decision_s}'. "
                         f"Must be one of: {list(decision_map.keys())}"
            }), 400

        decision = decision_map[decision_s]

        # Retrieve and update the alert
        alert = queue.get(alert_id)
        if alert is None:
            return jsonify({"error": f"Alert '{alert_id}' not found."}), 404

        if alert.decision != Decision.PENDING:
            return jsonify({
                "error": f"Alert '{alert_id}' is already decided as "
                         f"'{alert.decision.value}'. Cannot change.",
                "alert": alert.to_dict(),
            }), 409

        updated_alert = queue.decide(alert_id, decision, decided_by=decided_by)
        if updated_alert is None:
            return jsonify({"error": "Decision failed (internal error)."}), 500

        logger.info(
            "[API] Decision received: alert=%s decision=%s by=%s",
            alert_id, decision_s, decided_by,
        )

        response = {
            "status": "ok",
            "alert": updated_alert.to_dict(),
            "mitigation": None,
        }

        # Trigger mitigation if user approved
        if decision == Decision.APPROVED:
            logger.info(
                "[API] Operator APPROVED alert %s - triggering mitigation for %s",
                alert_id, updated_alert.src_ip,
            )
            try:
                mit_result = mitigator.from_alert(
                    updated_alert,
                    action=MitigationAction.BLOCK,
                )
                response["mitigation"] = mit_result.to_dict()

                if mit_result.status.value == "success":
                    logger.info(
                        "[API] Mitigation SUCCESS: %s via %s",
                        mit_result.summary(), mit_result.method,
                    )
                else:
                    logger.warning(
                        "[API] Mitigation FAILED: %s", mit_result.error
                    )

            except Exception as exc:
                logger.error("[API] Mitigation exception: %s", exc, exc_info=True)
                response["mitigation"] = {
                    "status": "failed",
                    "error":  str(exc),
                }

        return jsonify(response), 200

   
    """  Stats endpoint
    Return queue summary counts for the dashboard status bar.
    Response shape:
      { "queue": { "total": N, "by_state": {...}, "by_severity": {...} },
        "scan": { "last_scan_at": ..., "total_scans": N, ... },
        "uptime_s": N }
    """
    @app.route("/api/stats", methods=["GET"])
    def get_stats():
        with scan_lock:
            scan_info = dict(scan_meta)

        return jsonify({
            "queue": queue.stats(),
            "scan": scan_info,
            "uptime_s": round(time.time() - start_time, 1),
        })

    
    """  Mitigation endpoints
    Return the contents of the mitigation audit log (results/mitigator.log).
    Query parameters: ?lines=N   — return the last N lines (default: 50)
    """
    @app.route("/api/mitigation/log", methods=["GET"])
    def get_mitigation_log():
        log_path = os.path.join("results", "mitigator.log")
        n_lines = int(request.args.get("lines", "50"))
        if not os.path.exists(log_path):
            return jsonify({
                "log": [],
                "note": "No mitigation log yet, no approvals have been made.",
            })

        with open(log_path, "r") as f:
            all_lines = f.readlines()

        recent = [l.rstrip("\n") for l in all_lines[-n_lines:]]
        return jsonify({"log": recent, "total_lines": len(all_lines)})

    """
    Run ovs-ofctl dump-flows and filter for Tool 4 (HITL) rules.
    Query parameters: ?dpid=N - switch DPID to query (default: 1 = s1)
    Returns the raw ovs-ofctl output lines or an error message if
    ovs-ofctl is not available, i.e. not running inside the Mininet.
    """
    @app.route("/api/mitigation/verify", methods=["GET"])
    def verify_mitigation():
        dpid = int(request.args.get("dpid", "1"))
        output = verify_rule_installed(dpid)
        return jsonify({"dpid": dpid, "rules": output})

    # Manually unblock a host and remove the Tool 4 DROP rule.
    @app.route("/api/mitigation/unblock", methods=["POST"])
    def unblock_host():
        body = request.get_json(silent=True)
        if not body:
            return jsonify({"error": "Request body must be JSON."}), 400

        src_ip = body.get("src_ip", "")
        dst_port = int(body.get("dst_port", 0))
        protocol = body.get("protocol", "tcp")
        dpid = int(body.get("dpid", 1))
        alert_id = body.get("alert_id", "manual")
        if not src_ip:
            return jsonify({"error": "Missing field: src_ip"}), 400

        result = mitigator.unblock(
            src_ip = src_ip,
            dst_port = dst_port,
            protocol = protocol,
            dpid = dpid,
            alert_id = alert_id,
        )
        return jsonify(result.to_dict()), 200

    
    """  Scan trigger
    Trigger an immediate detection scan on demand. press a button in the 
    dashboard to force a fresh scan without waiting for the auto-scan timer.
    Returns the number of new alerts created.
    """
    @app.route("/api/scan", methods=["POST"])
    def trigger_scan():
        body = request.get_json(silent=True) or {}
        override_data = body.get("data_path")

        # Temporarily override data path if provided
        nonlocal_data = data_path
        if override_data and os.path.exists(override_data):
            # We can't trivially rebind the outer closure variable,
            # so we patch the scan function inline via a one-off call
            try:
                import joblib
                from src.detect import detect

                bundle = joblib.load(model_path)
                df = detect(model_path, override_data, verbose=False)
                new_alerts = alerts_from_detections(
                    df, bundle,
                    min_confidence = MIN_ALERT_CONFIDENCE,
                    max_alerts = MAX_ALERTS_PER_SCAN,
                )
                for alert in new_alerts:
                    queue.push(alert)

                with scan_lock:
                    scan_meta["last_scan_at"] = time.time()
                    scan_meta["last_scan_count"] = len(new_alerts)
                    scan_meta["total_scans"] += 1

                return jsonify({
                    "new_alerts": len(new_alerts),
                    "data_path": override_data,
                    "pending": len(queue.pending()),
                }), 200

            except Exception as exc:
                return jsonify({"error": str(exc)}), 500

        # Default: scan the startup data path
        n = run_scan(verbose=False)
        return jsonify({
            "new_alerts": n,
            "data_path": data_path,
            "pending": len(queue.pending()),
        }), 200


    """  Health check
    Health check endpoint is used by the dashboard to confirm the
    server is reachable and show uptime.
    """
    @app.route("/api/health", methods=["GET"])
    def health_check():
        with scan_lock:
            scan_info = dict(scan_meta)

        return jsonify({
            "status": "ok",
            "uptime_s": round(time.time() - start_time, 1),
            "queue_size": len(queue),
            "pending": len(queue.pending()),
            "model_path": model_path,
            "data_path": data_path,
            "auto_scan": auto_scan,
            "scan_interval": AUTO_SCAN_INTERVAL,
            "last_scan": scan_info.get("last_scan_at"),
        })


    # Error handlers
    @app.errorhandler(404)
    def not_found(exc):
        return jsonify({"error": str(exc)}), 404

    @app.errorhandler(405)
    def method_not_allowed(exc):
        return jsonify({"error": "Method not allowed."}), 405

    @app.errorhandler(500)
    def internal_error(exc):
        logger.error("Internal server error: %s", exc, exc_info=True)
        return jsonify({"error": "Internal server error."}), 500

    return app

# cli entry point
def main():
    parser = argparse.ArgumentParser(
        prog = "dashboard/app.py",
        description = "Tool 4: HITL Operator Dashboard Server",
    )
    parser.add_argument(
        "--model",
        default = os.environ.get("MODEL_PATH", "models/global.pkl"),
        help = "Path to trained model bundle (.pkl) [default: models/global.pkl]",
    )
    parser.add_argument(
        "--data",
        default = os.environ.get("DATA_PATH", "data/new_flows.csv"),
        help = "Path to flow CSV to scan [default: data/new_flows.csv]",
    )
    parser.add_argument(
        "--port",
        type = int,
        default = DASHBOARD_PORT,
        help = f"Port to listen on [default: {DASHBOARD_PORT}]",
    )
    parser.add_argument(
        "--host",
        default = DASHBOARD_HOST,
        help = f"Host to bind [default: {DASHBOARD_HOST}]",
    )
    parser.add_argument(
        "--no-auto-scan",
        action = "store_true",
        help = "Disable background auto-scanning (manual /api/scan only)",
    )
    parser.add_argument(
        "--debug",
        action = "store_true",
        help = "Enable Flask debug mode (do not use in Mininet live demo)",
    )
    args = parser.parse_args()

    logger.info("+-" * 30)
    logger.info("[*] Tool 4 HITL Operator Dashboard")
    logger.info("[*] Model: %s", args.model)
    logger.info("[*] Data: %s", args.data)
    logger.info("[*] URL: http://localhost:%d", args.port)
    logger.info("[*] API: http://localhost:%d/api/alerts", args.port)
    logger.info("+-" * 30)

    app = create_app(
        model_path = args.model,
        data_path = args.data,
        auto_scan = not args.no_auto_scan,
    )
    app.run(
        host = args.host,
        port = args.port,
        debug = args.debug,
        use_reloader = False,   # reloader breaks the background scanner thread
    )


if __name__ == "__main__":
    main()
