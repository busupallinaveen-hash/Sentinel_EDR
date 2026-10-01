#!/usr/bin/env python3
"""
server/central_server.py — SentinelEDR Central Management Server

Aggregates alerts from multiple SentinelEDR agents across a network.
Agents POST their alerts to this server; the server correlates across endpoints.

Features:
  - Multi-agent alert collection via REST API
  - Cross-endpoint attack correlation (same attacker on multiple hosts)
  - Aggregated dashboard at /dashboard
  - Alert forwarding to SIEM integrations
  - Node registry (which agents are online)

Run separately from the agent:
  python server/central_server.py --port 9000

Agents register by setting in sentinel.yaml:
  server:
    central_server_url: "http://<server-ip>:9000"
    node_id: "workstation-01"
"""

import json, logging, os, platform, socket, threading, time
from collections import defaultdict, deque
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse

log = logging.getLogger("SentinelEDR.CentralServer")

DEFAULT_PORT  = 9000
MAX_ALERTS    = 50000
STALE_NODE_S  = 120   # node considered offline if no heartbeat in 2 min


class NodeRegistry:
    """Tracks all connected SentinelEDR agents."""

    def __init__(self):
        self._nodes = {}   # node_id → {ip, hostname, last_seen, alert_count, status}
        self._lock  = threading.Lock()

    def register(self, node_id: str, ip: str, hostname: str = ""):
        with self._lock:
            existing = self._nodes.get(node_id, {})
            self._nodes[node_id] = {
                "node_id":     node_id,
                "ip":          ip,
                "hostname":    hostname or existing.get("hostname", ""),
                "last_seen":   time.time(),
                "first_seen":  existing.get("first_seen", time.time()),
                "alert_count": existing.get("alert_count", 0),
                "status":      "online",
            }

    def heartbeat(self, node_id: str):
        with self._lock:
            if node_id in self._nodes:
                self._nodes[node_id]["last_seen"] = time.time()
                self._nodes[node_id]["status"]    = "online"

    def increment_alerts(self, node_id: str, count: int = 1):
        with self._lock:
            if node_id in self._nodes:
                self._nodes[node_id]["alert_count"] += count

    def get_all(self) -> list:
        with self._lock:
            now   = time.time()
            nodes = []
            for n in self._nodes.values():
                n = dict(n)
                n["status"] = "online" if (now - n["last_seen"]) < STALE_NODE_S else "offline"
                nodes.append(n)
            return nodes

    def online_count(self) -> int:
        now = time.time()
        with self._lock:
            return sum(1 for n in self._nodes.values()
                       if (now - n["last_seen"]) < STALE_NODE_S)


class AlertCorrelator:
    """
    Cross-endpoint correlation engine.
    Detects the same attacker IP appearing on multiple hosts (lateral movement).
    Detects coordinated attack patterns across endpoints (worm/ransomware spread).
    """

    def __init__(self):
        # attacker_ip → list of (node_id, timestamp, alert_title)
        self._ip_hits: dict[str, list] = defaultdict(list)
        # alert_type → list of (node_id, timestamp)
        self._type_hits: dict[str, list] = defaultdict(list)
        self._incidents = deque(maxlen=500)
        self._lock = threading.Lock()

    def ingest(self, node_id: str, alert: dict):
        now = time.time()
        atype = alert.get("type", "")
        proc  = alert.get("process", {})

        # Track by attacker IP
        for ip_key in ["attacker_ip", "remote_ip"]:
            ip = proc.get(ip_key)
            if ip:
                with self._lock:
                    self._ip_hits[ip].append({
                        "node_id": node_id,
                        "ts":      now,
                        "title":   alert.get("title", ""),
                    })
                    # Deduplicate old entries
                    cutoff = now - 600  # 10-min window
                    self._ip_hits[ip] = [
                        h for h in self._ip_hits[ip] if h["ts"] > cutoff
                    ]
                    # Alert if same IP hit multiple nodes
                    nodes_hit = {h["node_id"] for h in self._ip_hits[ip]}
                    if len(nodes_hit) >= 2:
                        self._fire_incident(
                            "CROSS_ENDPOINT_LATERAL_MOVEMENT",
                            f"Attacker {ip} seen on {len(nodes_hit)} endpoints",
                            f"Same source IP {ip} triggered alerts on: "
                            f"{', '.join(nodes_hit)}. Possible lateral movement.",
                            "CRITICAL", list(nodes_hit)
                        )

        # Track ransomware spread
        if atype in ("RANSOMWARE_ENTROPY", "RANSOMWARE_VELOCITY"):
            with self._lock:
                self._type_hits[atype].append({"node_id": node_id, "ts": now})
                cutoff = now - 300
                self._type_hits[atype] = [
                    h for h in self._type_hits[atype] if h["ts"] > cutoff
                ]
                nodes_ransomware = {h["node_id"] for h in self._type_hits[atype]}
                if len(nodes_ransomware) >= 2:
                    self._fire_incident(
                        "RANSOMWARE_SPREAD_DETECTED",
                        f"Ransomware on {len(nodes_ransomware)} endpoints",
                        f"Ransomware indicators on: {', '.join(nodes_ransomware)}. "
                        f"Possible worm/ransomware campaign in progress.",
                        "CRITICAL", list(nodes_ransomware)
                    )

    def _fire_incident(self, itype: str, title: str, desc: str,
                       severity: str, nodes: list):
        key = f"{itype}:{':'.join(sorted(nodes))}"
        # Check dedup without holding lock
        now = time.time()
        for inc in list(self._incidents):
            if inc.get("key") == key and (now - inc.get("ts", 0)) < 300:
                return
        incident = {
            "key":         key,
            "type":        itype,
            "title":       title,
            "description": desc,
            "severity":    severity,
            "nodes":       nodes,
            "ts":          time.time(),
            "timestamp":   datetime.now().isoformat(),
        }
        self._incidents.append(incident)
        log.critical(f"[CORRELATION] 🔴 {title}")

    def get_incidents(self) -> list:
        with self._lock:
            return list(self._incidents)


class CentralAlertStore:
    """Stores all alerts received from all nodes."""

    def __init__(self, persist_path: str = "/tmp/sentinel_central_alerts.json"):
        self._alerts      = deque(maxlen=MAX_ALERTS)
        self._by_node     = defaultdict(list)
        self._lock        = threading.Lock()
        self._persist     = persist_path
        self._counts      = defaultdict(lambda: defaultdict(int))  # node→severity→count

    def add(self, node_id: str, alert: dict):
        alert["_node_id"]   = node_id
        alert["_received"]  = datetime.now().isoformat()
        with self._lock:
            self._alerts.append(alert)
            self._by_node[node_id].append(alert)
            if len(self._by_node[node_id]) > 5000:
                self._by_node[node_id] = self._by_node[node_id][-5000:]
            self._counts[node_id][alert.get("severity", "INFO")] += 1

    def get_recent(self, n: int = 200, node_id: str = None) -> list:
        with self._lock:
            if node_id:
                return list(self._by_node.get(node_id, []))[-n:]
            return list(self._alerts)[-n:]

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "total":    len(self._alerts),
                "by_node":  dict(self._counts),
            }


# ── HTTP Handler ──────────────────────────────────────────────────────────────

CENTRAL_HTML = """<!DOCTYPE html>
<html><head><title>SentinelEDR Central</title>
<style>
body{background:#0d1117;color:#e6edf3;font-family:system-ui;padding:24px;margin:0}
h1{color:#74c0fc;margin-bottom:24px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:16px;margin-bottom:32px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px}
.card h3{font-size:12px;color:#8b949e;text-transform:uppercase;margin-bottom:8px}
.card .val{font-size:28px;font-weight:700}
.online{color:#69db7c}.offline{color:#ff6b6b}.count{color:#74c0fc}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:8px;color:#8b949e;border-bottom:1px solid #30363d;font-size:11px}
td{padding:8px;border-bottom:1px solid #21262d}
.badge{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}
.CRITICAL{background:rgba(255,107,107,.2);color:#ff6b6b}
.HIGH{background:rgba(255,169,77,.2);color:#ffa94d}
.MEDIUM{background:rgba(255,212,59,.2);color:#ffd43b}
.LOW{background:rgba(116,192,252,.2);color:#74c0fc}
</style></head>
<body>
<h1>⚔️ SentinelEDR Central Management</h1>
<div class="grid" id="stats">Loading...</div>
<h2 style="margin-bottom:12px;font-size:15px">Connected Nodes</h2>
<table id="nodeTable"><thead><tr><th>Node ID</th><th>IP</th><th>Status</th><th>Alerts</th><th>Last Seen</th></tr></thead>
<tbody id="nodeBody"></tbody></table>
<h2 style="margin:24px 0 12px;font-size:15px">Correlation Incidents</h2>
<table id="incTable"><thead><tr><th>Severity</th><th>Incident</th><th>Nodes</th><th>Time</th></tr></thead>
<tbody id="incBody"></tbody></table>
<script>
async function refresh(){
  try{
    const [s,n,i]=await Promise.all([fetch('/api/stats'),fetch('/api/nodes'),fetch('/api/incidents')]);
    const stats=await s.json(),nodes=await n.json(),incs=await i.json();
    document.getElementById('stats').innerHTML=`
      <div class="card"><h3>Total Alerts</h3><div class="val count">${stats.total||0}</div></div>
      <div class="card"><h3>Online Nodes</h3><div class="val online">${stats.online_nodes||0}</div></div>
      <div class="card"><h3>Correlation Incidents</h3><div class="val" style="color:#da77f2">${(incs.incidents||[]).length}</div></div>`;
    document.getElementById('nodeBody').innerHTML=(nodes.nodes||[]).map(n=>`<tr>
      <td>${n.node_id}</td><td>${n.ip}</td>
      <td><span class="${n.status}">${n.status}</span></td>
      <td>${n.alert_count}</td>
      <td style="color:#8b949e">${new Date(n.last_seen*1000).toLocaleTimeString()}</td></tr>`).join('');
    document.getElementById('incBody').innerHTML=(incs.incidents||[]).slice().reverse().map(i=>`<tr>
      <td><span class="badge ${i.severity}">${i.severity}</span></td>
      <td>${i.title}</td><td style="color:#8b949e">${(i.nodes||[]).join(', ')}</td>
      <td style="color:#8b949e">${(i.timestamp||'').slice(11,19)}</td></tr>`).join('')
      ||'<tr><td colspan="4" style="color:#8b949e;text-align:center">No incidents</td></tr>';
  }catch(e){console.error(e)}
}
setInterval(refresh,5000);refresh();
</script></body></html>"""


class CentralHandler(BaseHTTPRequestHandler):
    store      = None
    registry   = None
    correlator = None

    def log_message(self, *args): pass

    def _json(self, data, code=200):
        body = json.dumps(data, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", 0))
            return json.loads(self.rfile.read(length)) if length else {}
        except Exception:
            return {}

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/dashboard"):
            body = CENTRAL_HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/alerts":
            alerts = self.store.get_recent(200) if self.store else []
            self._json({"alerts": alerts})
        elif path == "/api/stats":
            stats = self.store.get_stats() if self.store else {}
            stats["online_nodes"] = self.registry.online_count() if self.registry else 0
            self._json(stats)
        elif path == "/api/nodes":
            nodes = self.registry.get_all() if self.registry else []
            self._json({"nodes": nodes})
        elif path == "/api/incidents":
            incs = self.correlator.get_incidents() if self.correlator else []
            self._json({"incidents": incs})
        else:
            self.send_response(404); self.end_headers()

    def do_POST(self):
        path = urlparse(self.path).path
        body = self._read_body()
        client_ip = self.client_address[0]

        if path == "/api/register":
            node_id  = body.get("node_id", client_ip)
            hostname = body.get("hostname", "")
            self.registry.register(node_id, client_ip, hostname)
            log.info(f"Node registered: {node_id} ({client_ip})")
            self._json({"status": "registered", "node_id": node_id})

        elif path == "/api/heartbeat":
            node_id = body.get("node_id", client_ip)
            self.registry.heartbeat(node_id)
            self._json({"status": "ok"})

        elif path == "/api/alerts":
            node_id = body.get("node_id", client_ip)
            alerts  = body.get("alerts", [])
            if isinstance(alerts, dict):
                alerts = [alerts]
            for alert in alerts:
                self.store.add(node_id, alert)
                self.correlator.ingest(node_id, alert)
            self.registry.increment_alerts(node_id, len(alerts))
            self._json({"status": "ok", "received": len(alerts)})

        else:
            self.send_response(404); self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


class CentralServer:
    def __init__(self, port: int = DEFAULT_PORT):
        self._port       = port
        self._store      = CentralAlertStore()
        self._registry   = NodeRegistry()
        self._correlator = AlertCorrelator()
        self._server     = None

    def start(self):
        CentralHandler.store      = self._store
        CentralHandler.registry   = self._registry
        CentralHandler.correlator = self._correlator

        self._server = HTTPServer(("0.0.0.0", self._port), CentralHandler)
        log.info(f"Central server running on port {self._port}")
        print(f"\n  🌐 Central Dashboard → http://localhost:{self._port}/dashboard")
        print(f"  📡 Agent endpoint   → http://localhost:{self._port}/api/alerts\n")
        try:
            self._server.serve_forever()
        except KeyboardInterrupt:
            log.info("Central server stopped")


if __name__ == "__main__":
    import argparse
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")
    parser = argparse.ArgumentParser(description="SentinelEDR Central Server")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()
    CentralServer(port=args.port).start()
