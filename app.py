
import csv
import io
import json
import os
import re
import socket
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, Response, render_template, request, jsonify

app = Flask(__name__)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_history.db")

SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 587: "SMTP (Submission)", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle DB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP Proxy", 8443: "HTTPS Alt", 27017: "MongoDB",
}

PRESETS = {
    "web":           {"label": "Web",           "ports": [80, 443, 8080, 8443]},
    "email":         {"label": "Email",         "ports": [25, 110, 143, 465, 587, 993, 995]},
    "database":      {"label": "Database",      "ports": [1433, 3306, 5432, 6379, 27017]},
    "remote_access": {"label": "Remote Access", "ports": [22, 23, 3389, 5900]},
    "common":        {"label": "Common",        "ports": [21, 22, 23, 25, 53, 80, 110, 143,
                                                          443, 993, 995, 3306, 3389, 5432, 8080]},
}


THROTTLE_PRESETS = {
    "sneaky":     {"label": "Sneaky",     "timeout": 2.0,  "max_threads": 10},
    "normal":     {"label": "Normal",     "timeout": 0.5,  "max_threads": 100},
    "aggressive": {"label": "Aggressive", "timeout": 0.2,  "max_threads": 200},
}

DEFAULT_TIMEOUT = 0.5
DEFAULT_MAX_THREADS = 100


def _get_db():
    """Return a new connection to the SQLite history database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db():
    """Create the scans table if it doesn't exist."""
    with _get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT    NOT NULL,
                target      TEXT    NOT NULL,
                resolved_ip TEXT    NOT NULL,
                ports_scanned INTEGER NOT NULL,
                open_ports_json TEXT NOT NULL,
                scan_time   REAL    NOT NULL
            )
        """)


_init_db()


def _is_valid_ip(ip: str) -> bool:
    """Basic IPv4 validation."""
    pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if not re.match(pattern, ip):
        return False
    return all(0 <= int(octet) <= 255 for octet in ip.split("."))


def _is_valid_hostname(hostname: str) -> bool:
    """Basic hostname validation."""
    pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
    return bool(re.match(pattern, hostname))


def _grab_banner(target: str, port: int, timeout: float = 1.0) -> str:
    """Attempt to grab a service banner from an open port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((target, port))
            # Some services send a banner immediately; others need a nudge.
            try:
                # Try receiving first (works for SSH, FTP, SMTP, etc.)
                banner = sock.recv(1024)
                if banner:
                    return banner.decode("utf-8", errors="replace").strip()
            except socket.timeout:
                pass
            # Send a minimal HTTP-style probe for web servers
            if port in (80, 443, 8080, 8443):
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                try:
                    banner = sock.recv(1024)
                    if banner:
                        # Return just the first line (e.g. "HTTP/1.1 200 OK")
                        first_line = banner.decode("utf-8", errors="replace").split("\r\n")[0]
                        return first_line.strip()
                except socket.timeout:
                    pass
    except (socket.error, OSError):
        pass
    return ""


def scan_port(target: str, port: int, timeout: float = 0.5) -> dict | None:
    """Try to connect to a single port. Returns info dict if open, else None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            if result == 0:
                banner = _grab_banner(target, port, timeout=max(timeout, 1.0))
                return {
                    "port": port,
                    "service": SERVICE_NAMES.get(port, "Unknown"),
                    "banner": banner,
                }
    except (socket.error, OSError):
        pass
    return None


def scan_ports(target: str, ports: list[int],
               timeout: float = DEFAULT_TIMEOUT,
               max_threads: int = DEFAULT_MAX_THREADS) -> list[dict]:
    """Scan a list of ports concurrently and return open ones."""
    open_ports = []
    workers = min(max_threads, len(ports))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(scan_port, target, p, timeout): p for p in ports}
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                open_ports.append(result)
    open_ports.sort(key=lambda x: x["port"])
    return open_ports


def _parse_custom_ports(raw: str) -> list[int]:
    """Parse a comma-separated string of ports, validate and dedupe."""
    ports = set()
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        val = int(token)  # raises ValueError if not int
        if not (1 <= val <= 65535):
            raise ValueError(f"Port {val} out of range")
        ports.add(val)
    return sorted(ports)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/presets")
def get_presets():
    return jsonify(PRESETS)


@app.route("/throttle-presets")
def get_throttle_presets():
    return jsonify(THROTTLE_PRESETS)


@app.route("/scan", methods=["POST"])
def do_scan():
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    preset = data.get("preset")            # optional preset key
    custom_ports = data.get("custom_ports") # optional comma-separated

    # ── Throttle settings ─────────────────────────────────────────
    throttle_key = data.get("throttle")
    if throttle_key and throttle_key in THROTTLE_PRESETS:
        timeout = THROTTLE_PRESETS[throttle_key]["timeout"]
        max_threads = THROTTLE_PRESETS[throttle_key]["max_threads"]
    else:
        try:
            timeout = float(data.get("timeout", DEFAULT_TIMEOUT))
            max_threads = int(data.get("max_threads", DEFAULT_MAX_THREADS))
        except (ValueError, TypeError):
            timeout = DEFAULT_TIMEOUT
            max_threads = DEFAULT_MAX_THREADS
        timeout = max(0.1, min(timeout, 5.0))
        max_threads = max(1, min(max_threads, 200))


    if not target:
        return jsonify({"error": "Target IP or hostname is required."}), 400

    resolved_ip = target
    if not _is_valid_ip(target):
        if _is_valid_hostname(target):
            try:
                resolved_ip = socket.gethostbyname(target)
            except socket.gaierror:
                return jsonify({"error": f"Cannot resolve hostname: {target}"}), 400
        else:
            return jsonify({"error": "Invalid IP address or hostname."}), 400

    # ── Determine ports to scan ───────────────────────────────────
    if preset and preset in PRESETS:
        ports = PRESETS[preset]["ports"]
    elif custom_ports:
        try:
            ports = _parse_custom_ports(custom_ports)
        except ValueError as e:
            return jsonify({"error": f"Invalid custom ports: {e}"}), 400
        if not ports:
            return jsonify({"error": "No valid ports provided."}), 400
        if len(ports) > 10000:
            return jsonify({"error": "Maximum 10,000 custom ports allowed."}), 400
    else:
        try:
            start_port = int(data.get("start_port", 1))
            end_port = int(data.get("end_port", 1024))
        except (ValueError, TypeError):
            return jsonify({"error": "Port values must be integers."}), 400

        if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
            return jsonify({"error": "Ports must be between 1 and 65535."}), 400
        if start_port > end_port:
            return jsonify({"error": "Start port must be ≤ end port."}), 400
        if (end_port - start_port + 1) > 10000:
            return jsonify({"error": "Maximum range is 10,000 ports per scan."}), 400

        ports = list(range(start_port, end_port + 1))

    # ── Scan ──────────────────────────────────────────────────────
    t0 = time.time()
    open_ports = scan_ports(resolved_ip, ports,
                            timeout=timeout, max_threads=max_threads)
    elapsed = round(time.time() - t0, 2)

    result = {
        "target": target,
        "resolved_ip": resolved_ip,
        "ports_scanned": len(ports),
        "open_ports": open_ports,
        "scan_time": elapsed,
    }

    # ── Save to history ───────────────────────────────────────────
    try:
        with _get_db() as conn:
            conn.execute(
                """INSERT INTO scans
                   (timestamp, target, resolved_ip, ports_scanned, open_ports_json, scan_time)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    time.strftime("%Y-%m-%d %H:%M:%S"),
                    target,
                    resolved_ip,
                    len(ports),
                    json.dumps(open_ports),
                    elapsed,
                ),
            )
            result["history_id"] = conn.execute(
                "SELECT last_insert_rowid()"
            ).fetchone()[0]
    except sqlite3.Error:
        pass  # Don't fail the scan if history write fails

    return jsonify(result)


# ── History routes ────────────────────────────────────────────────────
@app.route("/history")
def get_history():
    """Return last 50 scans."""
    with _get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT 50"
        ).fetchall()
    return jsonify([
        {
            "id": r["id"],
            "timestamp": r["timestamp"],
            "target": r["target"],
            "resolved_ip": r["resolved_ip"],
            "ports_scanned": r["ports_scanned"],
            "open_ports": json.loads(r["open_ports_json"]),
            "scan_time": r["scan_time"],
        }
        for r in rows
    ])


@app.route("/history", methods=["DELETE"])
def clear_history():
    """Delete all scan history."""
    with _get_db() as conn:
        conn.execute("DELETE FROM scans")
    return jsonify({"status": "ok"})


@app.route("/history/<int:scan_id>", methods=["DELETE"])
def delete_scan(scan_id):
    """Delete a single scan entry."""
    with _get_db() as conn:
        conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    return jsonify({"status": "ok"})


# ── Export routes ─────────────────────────────────────────────────────
@app.route("/export/<int:scan_id>/json")
def export_json(scan_id):
    """Download a scan result as a JSON file."""
    with _get_db() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not row:
        return jsonify({"error": "Scan not found."}), 404

    data = {
        "id": row["id"],
        "timestamp": row["timestamp"],
        "target": row["target"],
        "resolved_ip": row["resolved_ip"],
        "ports_scanned": row["ports_scanned"],
        "open_ports": json.loads(row["open_ports_json"]),
        "scan_time": row["scan_time"],
    }

    return Response(
        json.dumps(data, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.json"},
    )


@app.route("/export/<int:scan_id>/csv")
def export_csv(scan_id):
    """Download a scan result as a CSV file."""
    with _get_db() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not row:
        return jsonify({"error": "Scan not found."}), 404

    open_ports = json.loads(row["open_ports_json"])

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Scan ID", "Timestamp", "Target", "Resolved IP",
                      "Ports Scanned", "Scan Time (s)"])
    writer.writerow([row["id"], row["timestamp"], row["target"],
                      row["resolved_ip"], row["ports_scanned"], row["scan_time"]])
    writer.writerow([])
    writer.writerow(["Port", "Service", "Status", "Banner"])
    for p in open_ports:
        writer.writerow([p["port"], p["service"], "OPEN", p.get("banner", "")])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.csv"},
    )


# ── Entry point ───────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
