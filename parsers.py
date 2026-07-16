"""
CyberShield SIEM Dashboard — Flask backend.

Runs real security tools (when installed) via subprocess, streams live
output over WebSocket, normalizes results into a common event schema,
stores everything in SQLite, and serves a REST API + static frontend.

⚠️  Only ever point these tools at systems you own or are explicitly
    authorized to test. This backend does not enforce authorization —
    that responsibility belongs to the person running it.
"""

import json
import os
import re
import shlex
import shutil
import sqlite3
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone

from flask import Flask, jsonify, request, send_from_directory, g
from flask_cors import CORS
from flask_sock import Sock

import parsers as parser_mod

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "cybershield.db")
CONFIG_PATH = os.path.join(BASE_DIR, "tools_config.json")
STATIC_DIR = os.path.join(BASE_DIR, "static")

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="")
CORS(app)
sock = Sock(app)

# ---------------------------------------------------------------------------
# In-memory registries
# ---------------------------------------------------------------------------

TOOLS = {}                # tool_id -> config dict (with runtime "available" flag)
WS_CLIENTS = set()        # connected websocket clients
WS_LOCK = threading.Lock()
RUNS = {}                 # run_id -> run metadata (status, tool_id, target, started_at)


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS runs (
            id TEXT PRIMARY KEY,
            tool_id TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            target TEXT,
            params TEXT,
            status TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            exit_code INTEGER,
            raw_output TEXT
        );

        CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY,
            run_id TEXT,
            tool_id TEXT,
            timestamp TEXT NOT NULL,
            severity TEXT NOT NULL,
            source_ip TEXT,
            host TEXT,
            finding_type TEXT,
            message TEXT,
            raw TEXT,
            FOREIGN KEY(run_id) REFERENCES runs(id)
        );

        CREATE TABLE IF NOT EXISTS correlations (
            id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            source_ip TEXT,
            event_ids TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
        CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
        CREATE INDEX IF NOT EXISTS idx_events_run_id ON events(run_id);
        """
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Tool detection
# ---------------------------------------------------------------------------

def load_tools_config():
    with open(CONFIG_PATH, "r") as f:
        cfg = json.load(f)
    return cfg["tools"]


def detect_tool_availability(tool):
    """Check PATH (and special-cases like python modules) for a binary."""
    if tool.get("internal"):
        # e.g. httpx via the python httpx library rather than a CLI binary
        try:
            import httpx  # noqa: F401
            return True, "python module importable"
        except ImportError:
            return False, "python module not importable"

    binary = tool.get("binary")
    if binary and shutil.which(binary):
        return True, f"found at {shutil.which(binary)}"
    return False, "not found on PATH"


def refresh_tool_status():
    for tool in TOOLS.values():
        available, detail = detect_tool_availability(tool)
        tool["available"] = available
        tool["detail"] = detail


def init_tools():
    for tool in load_tools_config():
        TOOLS[tool["id"]] = tool
    refresh_tool_status()


# ---------------------------------------------------------------------------
# WebSocket broadcast helpers
# ---------------------------------------------------------------------------

def broadcast(message: dict):
    payload = json.dumps(message)
    dead = []
    with WS_LOCK:
        for ws in WS_CLIENTS:
            try:
                ws.send(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            WS_CLIENTS.discard(ws)


@sock.route("/ws")
def ws_endpoint(ws):
    with WS_LOCK:
        WS_CLIENTS.add(ws)
    try:
        while True:
            # We don't expect inbound messages, but reading keeps the
            # connection alive and lets us detect disconnects.
            msg = ws.receive(timeout=30)
            if msg is None:
                continue
    except Exception:
        pass
    finally:
        with WS_LOCK:
            WS_CLIENTS.discard(ws)


# ---------------------------------------------------------------------------
# Safe command construction
# ---------------------------------------------------------------------------

SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_./:\-@]+$")


def sanitize_param(value: str) -> str:
    """Reject shell metacharacters. We never invoke a shell, but this stops
    obviously malformed input (pipes, semicolons, backticks) from reaching
    subprocess argv entirely."""
    value = value.strip()
    if not value:
        return value
    if not SAFE_TOKEN_RE.match(value) and " " not in value:
        raise ValueError(f"Parameter contains disallowed characters: {value!r}")
    # allow spaces only for flag strings like "-sV -T4"
    for token in value.split():
        if not SAFE_TOKEN_RE.match(token):
            raise ValueError(f"Parameter contains disallowed characters: {token!r}")
    return value


def build_command(tool, params: dict):
    template = tool["command_template"]
    cmd = []
    for part in template:
        rendered = part
        for key, val in params.items():
            rendered = rendered.replace("{" + key + "}", val)
        if "{" in rendered and "}" in rendered:
            # unresolved placeholder (optional param not supplied) — skip token
            continue
        # split flag strings like "-sV -T4" into separate argv entries
        if part.startswith("{") and " " in rendered:
            cmd.extend(shlex.split(rendered))
        else:
            cmd.append(rendered)
    return cmd


# ---------------------------------------------------------------------------
# Tool execution
# ---------------------------------------------------------------------------

def run_tool_internal_httpx(target: str, run_id: str):
    """Special-cased runner for the bundled httpx python client, since it's
    the one tool guaranteed to be installed for a first end-to-end test."""
    import httpx as httpx_lib

    lines = []
    try:
        start = time.time()
        with httpx_lib.Client(follow_redirects=True, timeout=10) as client:
            resp = client.get(target)
        elapsed = round((time.time() - start) * 1000)
        line = (
            f"{target} -> HTTP {resp.status_code} "
            f"[{elapsed}ms] server={resp.headers.get('server', 'unknown')} "
            f"content-length={len(resp.content)}"
        )
        lines.append(line)
        broadcast({"type": "output", "run_id": run_id, "line": line})
        return 0, "\n".join(lines)
    except Exception as exc:
        line = f"ERROR: {exc}"
        lines.append(line)
        broadcast({"type": "output", "run_id": run_id, "line": line})
        return 1, "\n".join(lines)


def execute_run(run_id, tool, params):
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row

    broadcast({"type": "status", "run_id": run_id, "status": "running"})

    output_lines = []
    exit_code = 0

    try:
        if tool.get("internal") and tool["id"] == "httpx":
            exit_code, raw_output = run_tool_internal_httpx(params.get("target", ""), run_id)
            output_lines = raw_output.splitlines()
        else:
            cmd = build_command(tool, params)
            broadcast({"type": "output", "run_id": run_id, "line": f"$ {' '.join(cmd)}"})
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            for line in proc.stdout:
                line = line.rstrip("\n")
                output_lines.append(line)
                broadcast({"type": "output", "run_id": run_id, "line": line})
            proc.wait(timeout=tool.get("timeout_seconds", 300))
            exit_code = proc.returncode
    except FileNotFoundError:
        line = f"ERROR: binary '{tool.get('binary')}' not found. {tool.get('install', '')}"
        output_lines.append(line)
        broadcast({"type": "output", "run_id": run_id, "line": line})
        exit_code = 127
    except subprocess.TimeoutExpired:
        line = "ERROR: tool run timed out and was terminated."
        output_lines.append(line)
        broadcast({"type": "output", "run_id": run_id, "line": line})
        exit_code = 124
    except Exception as exc:
        line = f"ERROR: {exc}"
        output_lines.append(line)
        broadcast({"type": "output", "run_id": run_id, "line": line})
        exit_code = 1

    raw_output = "\n".join(output_lines)
    finished_at = datetime.now(timezone.utc).isoformat()
    status = "success" if exit_code == 0 else "failed"

    db.execute(
        "UPDATE runs SET status=?, finished_at=?, exit_code=?, raw_output=? WHERE id=?",
        (status, finished_at, exit_code, raw_output, run_id),
    )
    db.commit()

    # Parse output into normalized events
    parser_name = tool.get("parser", "generic")
    parse_fn = getattr(parser_mod, f"parse_{parser_name}", parser_mod.parse_generic)
    try:
        events = parse_fn(raw_output, target=params.get("target", ""))
    except Exception as exc:
        events = []
        broadcast({"type": "output", "run_id": run_id, "line": f"[parser error: {exc}]"})

    for ev in events:
        ev_id = str(uuid.uuid4())
        db.execute(
            """INSERT INTO events (id, run_id, tool_id, timestamp, severity, source_ip,
               host, finding_type, message, raw)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                ev_id,
                run_id,
                tool["id"],
                ev.get("timestamp", finished_at),
                ev.get("severity", "info"),
                ev.get("source_ip"),
                ev.get("host"),
                ev.get("finding_type", "finding"),
                ev.get("message", ""),
                json.dumps(ev),
            ),
        )
        broadcast({"type": "event", "event": {**ev, "id": ev_id, "tool_id": tool["id"]}})
    db.commit()

    run_correlation_engine(db)
    db.commit()
    db.close()

    broadcast({"type": "status", "run_id": run_id, "status": status, "exit_code": exit_code})
    RUNS[run_id]["status"] = status


# ---------------------------------------------------------------------------
# Correlation engine
# ---------------------------------------------------------------------------

def run_correlation_engine(db):
    """Very simple pattern correlation: if a host has 2+ open ports AND at
    least one medium+ severity finding, raise a combined-risk alert."""
    rows = db.execute(
        """SELECT source_ip, COUNT(*) as cnt,
           SUM(CASE WHEN severity IN ('high','critical') THEN 1 ELSE 0 END) as high_cnt
           FROM events WHERE source_ip IS NOT NULL AND source_ip != ''
           GROUP BY source_ip HAVING cnt >= 3"""
    ).fetchall()

    for row in rows:
        source_ip = row["source_ip"]
        existing = db.execute(
            "SELECT id FROM correlations WHERE source_ip=? AND title=?",
            (source_ip, "Multiple findings clustered on host"),
        ).fetchone()
        if existing:
            continue
        event_ids = [
            r["id"] for r in db.execute(
                "SELECT id FROM events WHERE source_ip=?", (source_ip,)
            ).fetchall()
        ]
        severity = "high" if row["high_cnt"] > 0 else "medium"
        db.execute(
            """INSERT INTO correlations (id, created_at, severity, title, description,
               source_ip, event_ids) VALUES (?,?,?,?,?,?,?)""",
            (
                str(uuid.uuid4()),
                datetime.now(timezone.utc).isoformat(),
                severity,
                "Multiple findings clustered on host",
                f"{row['cnt']} findings recorded against {source_ip}, "
                f"{row['high_cnt']} of which are high/critical severity.",
                source_ip,
                json.dumps(event_ids),
            ),
        )
        broadcast({"type": "correlation", "source_ip": source_ip, "severity": severity})


# ---------------------------------------------------------------------------
# REST API
# ---------------------------------------------------------------------------

@app.route("/api/tools")
def api_tools():
    refresh_tool_status()
    return jsonify(list(TOOLS.values()))


@app.route("/api/tools/<tool_id>/run", methods=["POST"])
def api_run_tool(tool_id):
    tool = TOOLS.get(tool_id)
    if not tool:
        return jsonify({"error": "unknown tool"}), 404
    if not tool.get("available"):
        return jsonify({
            "error": "tool not installed",
            "install": tool.get("install", "see documentation"),
        }), 400

    body = request.get_json(force=True, silent=True) or {}
    raw_params = body.get("params", {})

    # validate required params & sanitize
    params = {}
    try:
        for p in tool.get("params", []):
            val = raw_params.get(p["name"], p.get("default", ""))
            if p.get("required") and not val:
                return jsonify({"error": f"missing required param '{p['name']}'"}), 400
            if val:
                params[p["name"]] = sanitize_param(str(val))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    run_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc).isoformat()

    db = get_db()
    db.execute(
        """INSERT INTO runs (id, tool_id, tool_name, target, params, status, started_at)
           VALUES (?,?,?,?,?,?,?)""",
        (
            run_id,
            tool_id,
            tool["name"],
            params.get("target", ""),
            json.dumps(params),
            "queued",
            started_at,
        ),
    )
    db.commit()

    RUNS[run_id] = {"tool_id": tool_id, "status": "queued", "started_at": started_at}

    thread = threading.Thread(target=execute_run, args=(run_id, tool, params), daemon=True)
    thread.start()

    return jsonify({"run_id": run_id, "status": "queued"})


@app.route("/api/runs")
def api_runs():
    db = get_db()
    rows = db.execute("SELECT * FROM runs ORDER BY started_at DESC LIMIT 100").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/events")
def api_events():
    db = get_db()
    severity = request.args.get("severity")
    source_ip = request.args.get("source_ip")
    tool_id = request.args.get("tool_id")
    search = request.args.get("search")

    query = "SELECT * FROM events WHERE 1=1"
    args = []
    if severity:
        query += " AND severity=?"
        args.append(severity)
    if source_ip:
        query += " AND source_ip=?"
        args.append(source_ip)
    if tool_id:
        query += " AND tool_id=?"
        args.append(tool_id)
    if search:
        query += " AND (message LIKE ? OR host LIKE ? OR source_ip LIKE ?)"
        like = f"%{search}%"
        args.extend([like, like, like])
    query += " ORDER BY timestamp DESC LIMIT 500"

    rows = db.execute(query, args).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/events/<event_id>")
def api_event_detail(event_id):
    db = get_db()
    row = db.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(row))


@app.route("/api/correlations")
def api_correlations():
    db = get_db()
    rows = db.execute("SELECT * FROM correlations ORDER BY created_at DESC LIMIT 100").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/stats")
def api_stats():
    db = get_db()
    total_events = db.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
    by_severity = {
        r["severity"]: r["c"]
        for r in db.execute(
            "SELECT severity, COUNT(*) c FROM events GROUP BY severity"
        ).fetchall()
    }
    by_type = {
        r["finding_type"]: r["c"]
        for r in db.execute(
            "SELECT finding_type, COUNT(*) c FROM events GROUP BY finding_type ORDER BY c DESC LIMIT 8"
        ).fetchall()
    }
    total_runs = db.execute("SELECT COUNT(*) c FROM runs").fetchone()["c"]
    recent = db.execute(
        "SELECT * FROM events ORDER BY timestamp DESC LIMIT 15"
    ).fetchall()

    # shield score: starts at 100, subtract weighted severity counts, floor 0
    weights = {"critical": 12, "high": 6, "medium": 3, "low": 1, "info": 0}
    penalty = sum(weights.get(sev, 0) * cnt for sev, cnt in by_severity.items())
    shield_score = max(0, 100 - penalty)

    # simple 14-point trend based on run history bucketed by day
    trend_rows = db.execute(
        """SELECT date(timestamp) d, COUNT(*) c FROM events
           GROUP BY d ORDER BY d DESC LIMIT 14"""
    ).fetchall()
    trend = list(reversed([{"date": r["d"], "count": r["c"]} for r in trend_rows]))

    return jsonify({
        "total_events": total_events,
        "total_runs": total_runs,
        "by_severity": by_severity,
        "by_type": by_type,
        "shield_score": shield_score,
        "trend": trend,
        "recent_events": [dict(r) for r in recent],
        "tools_available": sum(1 for t in TOOLS.values() if t.get("available")),
        "tools_total": len(TOOLS),
    })


@app.route("/api/export")
def api_export():
    fmt = request.args.get("format", "json")
    db = get_db()
    rows = [dict(r) for r in db.execute("SELECT * FROM events ORDER BY timestamp DESC").fetchall()]

    if fmt == "csv":
        import csv
        import io
        buf = io.StringIO()
        if rows:
            writer = csv.DictWriter(buf, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        return app.response_class(
            buf.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=cybershield_events.csv"},
        )

    return app.response_class(
        json.dumps(rows, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=cybershield_events.json"},
    )


# ---------------------------------------------------------------------------
# Static frontend
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


if __name__ == "__main__":
    init_db()
    init_tools()
    print(f"CyberShield starting — {sum(1 for t in TOOLS.values() if t['available'])}/"
          f"{len(TOOLS)} tools detected as available.")
    print("Only scan systems you own or are explicitly authorized to test.")
    app.run(host="0.0.0.0", port=5000, debug=False)
