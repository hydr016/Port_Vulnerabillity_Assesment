"""Flask web dashboard for the Port Scanning and Vulnerability Assessment module.

Run with:  python app.py   then open http://127.0.0.1:5000
"""
import json
import logging
import os
import threading
import time
from datetime import datetime

from flask import Flask, jsonify, render_template, request, send_from_directory

from models.schemas import (base_metadata, build_port_report,
                            build_vulnerability_report)
from scanner.nmap_scanner import NmapError, run_scan
from scanner.parser import ParseError, parse_nmap_xml
from scanner.validator import TargetError, validate_target
from scanner.vulnerability_engine import analyse_ports

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORT_FILES = {"port_scan.json", "vulnerabilities.json"}

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)


def load_config():
    with open(os.path.join(BASE_DIR, "config.json"), encoding="utf-8") as handle:
        return json.load(handle)


CONFIG = load_config()
OUTPUT_DIR = os.path.join(BASE_DIR, CONFIG.get("output_dir", "output"))
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Shared scan state (one scan at a time)
state_lock = threading.Lock()
state = {"status": "idle", "stage": "idle", "message": "Ready. Enter an authorized target.",
         "target": "", "started": None, "finished": None}


def set_state(**changes):
    with state_lock:
        state.update(changes)


def write_json(filename, data):
    """Write JSON atomically so the dashboard never reads a half-written file."""
    final_path = os.path.join(OUTPUT_DIR, filename)
    temp_path = final_path + ".tmp"
    with open(temp_path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
    os.replace(temp_path, final_path)


def write_reports(meta, ports, findings):
    write_json("port_scan.json", build_port_report(meta, ports))
    write_json("vulnerabilities.json", build_vulnerability_report(meta, findings))


def run_assessment(info):
    """Background job: scan -> parse -> assess -> write JSON reports."""
    scan_time = datetime.now().replace(microsecond=0).isoformat()
    started = time.time()
    try:
        set_state(stage="scanning", message=f"Scanning {info['address']} with Nmap. This can take a minute...")
        result = run_scan(info["address"], info["ip_version"], CONFIG)

        set_state(stage="analysing", message="Parsing results and running security checks...")
        host = parse_nmap_xml(result["xml"])
        if not host["host_up"]:
            raise NmapError("The target did not respond. It may be offline or blocking host "
                            "discovery. Set 'skip_host_discovery' to true in config.json to try again.")

        findings = analyse_ports(host["ports"])
        meta = base_metadata(
            info["target"], host["address"] or info["address"], host["hostname"], scan_time,
            "completed", nmap_version=host["nmap_version"],
            duration_seconds=round(time.time() - started, 1),
            nse_scripts_used=result["scripts_used"], notes=result["notes"])
        write_reports(meta, host["ports"], findings)

        if host["ports"]:
            message = (f"Scan completed: {len(host['ports'])} open port(s), "
                       f"{len(findings)} finding(s).")
        else:
            message = "Scan completed, but no open ports were found on this target."
        set_state(status="completed", stage="completed", message=message, finished=time.time())

    except (NmapError, ParseError) as exc:
        fail(info, scan_time, str(exc))
    except Exception:                      # never crash the dashboard
        logging.exception("Unexpected error during scan")
        fail(info, scan_time, "An unexpected error occurred. Check the terminal for details.")


def fail(info, scan_time, message):
    """Record a failed scan (reports are still written so other modules can read them)."""
    meta = base_metadata(info["target"], info["address"], "", scan_time, "failed", error=message)
    write_reports(meta, [], [])
    set_state(status="failed", stage="failed", message=message, finished=time.time())


# ------------------------------------------------------------------ routes
@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/scan", methods=["POST"])
def start_scan():
    body = request.get_json(silent=True) or {}
    if body.get("authorized") is not True:
        return jsonify(error="Confirm that you are authorized to scan this target."), 400
    try:
        info = validate_target(body.get("target"), CONFIG["allowed_networks"])
    except TargetError as exc:
        return jsonify(error=str(exc)), 400

    with state_lock:
        if state["status"] == "running":
            return jsonify(error="A scan is already running. Please wait for it to finish."), 409
        state.update(status="running", stage="validating", target=info["target"],
                     message="Target validated.", started=time.time(), finished=None)
    threading.Thread(target=run_assessment, args=(info,), daemon=True).start()
    return jsonify(message="Scan started."), 202


@app.route("/api/status")
def scan_status():
    with state_lock:
        return jsonify(dict(state))


@app.route("/api/results")
def results():
    data = {}
    for key, name in (("port_scan", "port_scan.json"), ("vulnerabilities", "vulnerabilities.json")):
        path = os.path.join(OUTPUT_DIR, name)
        try:
            with open(path, encoding="utf-8") as handle:
                data[key] = json.load(handle)
        except (OSError, ValueError):
            data[key] = None
    return jsonify(data)


@app.route("/files/<name>")
def report_file(name):
    if name not in REPORT_FILES:
        return jsonify(error="Unknown file."), 404
    return send_from_directory(OUTPUT_DIR, name, mimetype="application/json",
                               as_attachment=request.args.get("download") == "1")


if __name__ == "__main__":
    print('Only scan systems that you are explicitly authorized to test.')
    app.run(host=CONFIG.get("host", "127.0.0.1"), port=CONFIG.get("port", 5000), debug=False)
