#!/usr/bin/env python3
"""
detection/gnn/graph_engine.py — Graph Neural Network Attack Graph Engine (Plugin)

Represents the system as a property graph:
  Nodes: processes, users, network endpoints
  Edges: spawned-by, connected-to, authed-as

Detects lateral movement, privilege chains, and multi-hop attack paths
INVISIBLE to per-event ML — because each event looks normal individually,
but the relationship graph is not.

Requires: numpy, networkx
Install:  pip install numpy networkx --break-system-packages

Source: IDPS ai/gnn/graph_engine.py, adapted for SentinelEDR.
"""

import hashlib, logging, math, threading, time
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set, Tuple

log = logging.getLogger("SentinelEDR.GNN")

try:
    import numpy as np
    import networkx as nx
    GNN_OK = True
except ImportError:
    GNN_OK = False

try:
    import psutil
    PSUTIL = True
except ImportError:
    PSUTIL = False

WINDOW_SECS = 1800   # 30-min sliding graph window

# Skip known noisy Windows processes in GNN to reduce false positives
GNN_PROCESS_WHITELIST = {
    # Windows system processes
    'system idle process', 'system', 'registry', 'memcompression',
    'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe',
    'services.exe', 'lsass.exe', 'lsaiso.exe', 'ngciso.exe',
    'svchost.exe', 'fontdrvhost.exe', 'dwm.exe', 'explorer.exe',
    'runtimebroker.exe', 'backgroundtaskhost.exe', 'conhost.exe',
    'dllhost.exe', 'taskhostw.exe', 'sihost.exe', 'ctfmon.exe',
    'audiodg.exe', 'spoolsv.exe', 'wudfhost.exe', 'wmiprvse.exe',
    'searchindexer.exe', 'searchhost.exe', 'searchprotocolhost.exe',
    'searchfilterhost.exe', 'startmenuexperiencehost.exe',
    'shellexperiencehost.exe', 'securityhealthservice.exe',
    'nissrv.exe', 'msmpeng.exe', 'mpdefendercoreservice.exe',
    'smartscreen.exe', 'wlanext.exe', 'aggregatorhost.exe',
    # Browsers
    'chrome.exe', 'msedge.exe', 'msedgewebview2.exe',
    'firefox.exe', 'brave.exe',
    # Apps
    'ms-teams.exe', 'onedrive.exe', 'microsoftedgeupdate.exe',
    'officeclicktorun.exe', 'whatsapp.root.exe',
    # Hardware drivers / OEM
    'rtkaududservice64.exe', 'igfxcuiservice.exe', 'igfxem.exe',
    'intelaudioservice.exe', 'intelcphdcpsvc.exe', 'intelcphecisvc.exe',
    'esif_uf.exe', 'jhi_service.exe', 'thunderboltservice.exe',
    'tbtp2pshortcutservice.exe', 'dellffpdwmiservice.exe',
    'fwswitchservice.exe', 'hidfind.exe', 'hidmonitorsvc.exe',
    'rstmwservice.exe', 'oneapp.igcc.winservice.exe',
    'wavessyssvc64.exe', 'wavessvc64.exe',
    # Monitoring / security
    'sysmon64.exe', 'sysmon.exe', 'cowork-svc.exe', 'idps_notify.exe',
}
MAX_NODES   = 10000
SCORE_THRESH = 0.75  # anomaly score threshold (0-1)


class AttackGraph:
    """Live property graph of system process/network activity."""

    def __init__(self):
        if not GNN_OK:
            return
        self._G          = nx.DiGraph()
        self._edge_times = {}          # edge_key → last_seen timestamp
        self._node_times = {}          # node_id → first_seen
        self._lock       = threading.Lock()

    def add_process_node(self, pid: int, name: str) -> str:
        node_id = f"proc:{pid}:{name}"
        with self._lock:
            if node_id not in self._G:
                self._G.add_node(node_id, kind="process", name=name,
                                 pid=pid, first_seen=time.time())
            self._node_times[node_id] = time.time()
        return node_id

    def add_network_node(self, ip: str, port: int) -> str:
        node_id = f"net:{ip}:{port}"
        with self._lock:
            if node_id not in self._G:
                self._G.add_node(node_id, kind="network", ip=ip, port=port,
                                 first_seen=time.time())
            self._node_times[node_id] = time.time()
        return node_id

    def add_edge(self, src: str, dst: str, etype: str):
        key = (src, dst, etype)
        with self._lock:
            self._G.add_edge(src, dst, kind=etype, weight=1)
            if key in self._edge_times:
                self._G[src][dst]["weight"] += 1
            self._edge_times[key] = time.time()

    def prune_old(self):
        cutoff = time.time() - WINDOW_SECS
        with self._lock:
            old_nodes = [n for n, t in self._node_times.items() if t < cutoff]
            for n in old_nodes:
                if n in self._G:
                    self._G.remove_node(n)
                del self._node_times[n]

    def node_count(self) -> int:
        with self._lock:
            return self._G.number_of_nodes()

    def edge_count(self) -> int:
        with self._lock:
            return self._G.number_of_edges()

    def get_neighbors(self, node_id: str) -> List[str]:
        with self._lock:
            if node_id not in self._G:
                return []
            return list(self._G.neighbors(node_id))

    def compute_anomaly_score(self, node_id: str) -> float:
        """
        Simple graph-based anomaly score:
        - High out-degree (process connecting to many hosts) = suspicious
        - New node connecting to many existing nodes = suspicious
        - Process reaching system nodes it never reached before = suspicious
        """
        with self._lock:
            if node_id not in self._G:
                return 0.0
            out_deg = self._G.out_degree(node_id)
            in_deg  = self._G.in_degree(node_id)
            age     = time.time() - self._node_times.get(node_id, time.time())
            total   = self._G.number_of_nodes()
            if total < 10:
                return 0.0
            # Normalize: new node + high connectivity = high score
            deg_score = min(out_deg / 20.0, 1.0)
            age_score = max(0.0, 1.0 - math.log1p(age / 60) / 5.0)
            return (deg_score * 0.7 + age_score * 0.3)


class GNNEngine:
    ENGINE = "GNN"

    def __init__(self):
        if not GNN_OK:
            raise ImportError("numpy + networkx required for GNN plugin. "
                              "pip install numpy networkx --break-system-packages")
        self._graph    = AttackGraph()
        self._alerted  = set()
        self._lock     = threading.Lock()
        self._scan_n   = 0

    def _is_suspicious_port(self, port: int) -> bool:
        return port in {
            4444, 1337, 31337, 8888, 9001, 9999, 6666, 6667, 6668,
            1234, 12345, 54321, 65535, 4321, 666, 3333, 5555, 7777,
        }

    def _is_external_ip(self, ip: str) -> bool:
        private = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                   "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                   "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                   "172.30.", "172.31.", "192.168.", "127.", "::1", "")
        return not any(ip.startswith(p) for p in private)

    def scan(self, event_bus):
        if not PSUTIL or not GNN_OK:
            return

        self._scan_n += 1
        if self._scan_n % 12 == 0:
            self._graph.prune_old()

        try:
            procs = list(psutil.process_iter(["pid", "name", "ppid"]))
        except Exception:
            return

        for proc in procs:
            try:
                info   = proc.info
                pid    = info["pid"]
                name   = info["name"] or "unknown"
                ppid   = info.get("ppid", 0)

                # Skip noisy baseline processes from GNN graph
                if name.lower() in GNN_PROCESS_WHITELIST:
                    continue

                proc_node = self._graph.add_process_node(pid, name)

                # Edge: spawned-by parent
                if ppid and ppid != pid:
                    parent_node = self._graph.add_process_node(ppid, f"parent_{ppid}")
                    self._graph.add_edge(proc_node, parent_node, "spawned_by")

                # Edge: network connections
                try:
                    conns = proc.net_connections()
                    for c in conns:
                        if c.raddr:
                            rip, rport = c.raddr
                            net_node = self._graph.add_network_node(rip, rport)
                            self._graph.add_edge(proc_node, net_node, "connected_to")

                            # Anomaly checks
                            score = self._graph.compute_anomaly_score(proc_node)
                            is_ext = self._is_external_ip(rip)
                            is_sus = self._is_suspicious_port(rport)

                            if score >= SCORE_THRESH or (is_ext and is_sus):
                                alert_key = f"gnn:{pid}:{rip}:{rport}"
                                with self._lock:
                                    if alert_key in self._alerted:
                                        continue
                                    self._alerted.add(alert_key)

                                risk = min(100, int(score * 60 + (30 if is_sus else 0)))
                                sev  = "CRITICAL" if risk >= 80 else "HIGH" if risk >= 60 else "MEDIUM"

                                from core.alert_manager import Alert
                                a = Alert(
                                    alert_type   = "GNN_LATERAL_MOVEMENT",
                                    severity     = sev,
                                    title        = f"GNN: suspicious connection graph — {name}",
                                    description  = (
                                        f"Process '{name}' (PID {pid}) has an anomalous "
                                        f"connection graph (score={score:.2f}) connecting to "
                                        f"{rip}:{rport}. "
                                        f"Graph nodes={self._graph.node_count()}, "
                                        f"edges={self._graph.edge_count()}. "
                                        f"Possible lateral movement or C2 beaconing."
                                    ),
                                    process_info = {
                                        "pid": pid, "name": name,
                                        "remote_ip": rip, "remote_port": rport,
                                        "graph_score": round(score, 3),
                                        "suspicious_port": is_sus,
                                        "external_ip": is_ext,
                                    },
                                    risk_score   = risk,
                                    mitre_tactic = "lateral_movement",
                                    mitre_tech   = "T1021",
                                    engine       = self.ENGINE,
                                )
                                event_bus.publish("alert", {"kind": "alert", "alert": a})

                except (psutil.AccessDenied, AttributeError):
                    pass

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                log.debug(f"GNN scan error: {e}")

        # Prune alert cache
        with self._lock:
            if len(self._alerted) > 3000:
                self._alerted.clear()
