#!/usr/bin/env python3
"""
deception/honeypot_mesh.py — Honeypot Mesh (Zero False-Positive Deception Layer)

Deploys two deception layers:

1. FILE HONEYPOTS — decoy credential/key files placed in home dir.
   Any process touching these files = immediate CRITICAL alert.
   (Attackers enumerate files looking for credentials/keys)

2. NETWORK HONEYPOTS — fake services on unused ports (SSH:2222, HTTP:8080,
   FTP:2121, MySQL:3307). Any connection = attacker doing port scan/lateral move.
   Zero legitimate traffic expected = zero false positives.

Source: NeuralGuard HoneypotMesh + IDPS HoneypotManager, merged.
"""

import asyncio, hashlib, logging, os, platform, socket, threading, time
from datetime import datetime
from pathlib import Path
from typing import Callable, List, Optional

log    = logging.getLogger("SentinelEDR.HoneypotMesh")
SYSTEM = platform.system()

try:
    from watchdog.observers import Observer
    from watchdog.events    import FileSystemEventHandler
    WATCHDOG_OK = True
except ImportError:
    WATCHDOG_OK = False

try:
    import psutil
    PSUTIL = True
except ImportError:
    PSUTIL = False

# ── Decoy file definitions ─────────────────────────────────────────────────────

_HOME = Path.home()
_TMP  = Path(os.environ.get("TMPDIR", "/tmp"))

DECOY_FILES = [
    (_HOME / ".sentinel_decoy_credentials.json",
     b'{"aws_key":"AKIAIOSFODNN7EXAMPLE","secret":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}'),
    (_HOME / ".sentinel_decoy_id_rsa",
     b"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4\n-----END RSA PRIVATE KEY-----"),
    (_HOME / ".sentinel_decoy_passwd",
     b"root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000::/home/admin:/bin/bash"),
    (_HOME / ".sentinel_decoy_wallet.dat",
     b"\x04\x00\x00\x00\x01\x00\x00\x00fake_bitcoin_wallet_do_not_open"),
    (_HOME / ".sentinel_decoy_aws_config",
     b"[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = FAKEKEY"),
]

# ── Network honeypot banners ───────────────────────────────────────────────────

HONEYPOT_SERVICES = [
    (2222,  b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n",           "SSH"),
    (8080,  b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.52\r\n\r\n<html><title>Admin</title></html>", "HTTP"),
    (2121,  b"220 FTP Server Ready\r\n",                      "FTP"),
    (3307,  b"\x4a\x00\x00\x00\x0a\x38\x2e\x30\x2e\x32\x36", "MySQL"),
]


# ── File honeypot watchdog ─────────────────────────────────────────────────────

class _DecoyFileHandler(FileSystemEventHandler):
    def __init__(self, decoy_paths: set, callback: Callable):
        self._paths    = decoy_paths
        self._callback = callback

    def on_any_event(self, event):
        if event.is_directory:
            return
        if event.src_path in self._paths:
            self._callback(event.src_path, event.event_type)


class HoneypotMesh:
    ENGINE = "HoneypotMesh"

    def __init__(self):
        self._event_bus  = None
        self._alerted    = set()
        self._lock       = threading.Lock()
        self._decoy_paths = set()
        self._servers    = []

    # ── File honeypots ────────────────────────────────────────────────────────

    def _deploy_file_honeypots(self):
        deployed = []
        for path, content in DECOY_FILES:
            try:
                if not path.exists():
                    path.write_bytes(content)
                    try:
                        os.chmod(str(path), 0o600)
                    except Exception:
                        pass
                self._decoy_paths.add(str(path))
                deployed.append(str(path))
            except Exception as e:
                log.debug(f"Decoy deploy error {path}: {e}")
        log.info(f"File honeypots deployed: {len(deployed)} decoy files")

    def _on_decoy_access(self, path: str, event_type: str):
        alert_key = f"file:{path}:{event_type}"
        with self._lock:
            if alert_key in self._alerted:
                return
            self._alerted.add(alert_key)

        # Try to identify accessing process
        accessor = "unknown"
        if PSUTIL:
            try:
                for proc in psutil.process_iter(["pid", "name", "open_files"]):
                    try:
                        for f in proc.open_files():
                            if f.path == path:
                                accessor = f"{proc.name()} (PID {proc.pid})"
                                break
                    except Exception:
                        continue
            except Exception:
                pass

        from core.alert_manager import Alert
        a = Alert(
            alert_type   = "HONEYPOT_FILE_ACCESS",
            severity     = "CRITICAL",
            title        = f"Honeypot accessed: {Path(path).name}",
            description  = (
                f"Decoy file '{path}' was {event_type} by {accessor}. "
                f"No legitimate process should touch this file. "
                f"This is a ZERO FALSE-POSITIVE indicator of credential hunting or "
                f"file system enumeration attack."
            ),
            process_info = {"path": path, "event": event_type, "accessor": accessor},
            risk_score   = 97,
            mitre_tactic = "credential_access",
            mitre_tech   = "T1552",
            engine       = self.ENGINE,
        )
        if self._event_bus:
            self._event_bus.publish("alert", {"kind": "alert", "alert": a})
        log.critical(f"🍯 HONEYPOT HIT: {path} ({event_type}) by {accessor}")

    def _start_file_watcher(self):
        if not WATCHDOG_OK:
            log.warning("watchdog not installed — file honeypots disabled")
            return
        self._deploy_file_honeypots()
        observer = Observer()
        handler  = _DecoyFileHandler(self._decoy_paths, self._on_decoy_access)
        observer.schedule(handler, str(_HOME), recursive=False)
        observer.start()
        log.info("File honeypot watcher running")

    # ── Network honeypots ─────────────────────────────────────────────────────

    def _on_network_hit(self, port: int, service: str,
                        attacker_ip: str, attacker_port: int, data: bytes):
        alert_key = f"net:{attacker_ip}:{port}"
        with self._lock:
            if alert_key in self._alerted:
                return
            self._alerted.add(alert_key)

        snippet = data[:80].decode("utf-8", errors="replace").strip() if data else ""

        from core.alert_manager import Alert
        a = Alert(
            alert_type   = "HONEYPOT_NETWORK_HIT",
            severity     = "CRITICAL",
            title        = f"Network honeypot hit: {service} port {port}",
            description  = (
                f"Attacker {attacker_ip}:{attacker_port} connected to fake "
                f"{service} service on port {port}. "
                f"Data received: '{snippet}'. "
                f"ZERO FALSE-POSITIVE — no legitimate service runs on this port."
            ),
            process_info = {
                "attacker_ip": attacker_ip,
                "attacker_port": attacker_port,
                "honeypot_port": port,
                "service": service,
                "data_snippet": snippet,
            },
            risk_score   = 98,
            mitre_tactic = "discovery",
            mitre_tech   = "T1046",
            engine       = self.ENGINE,
        )
        if self._event_bus:
            self._event_bus.publish("alert", {"kind": "alert", "alert": a})
        log.critical(f"🍯 NETWORK HONEYPOT HIT: {service}:{port} from {attacker_ip}:{attacker_port}")

    def _serve_honeypot_port(self, port: int, banner: bytes, service: str):
        """Simple synchronous honeypot listener in its own thread."""
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", port))
            srv.listen(5)
            srv.settimeout(2.0)
            log.info(f"Network honeypot {service} on port {port}")
            while True:
                try:
                    conn, addr = srv.accept()
                    attacker_ip, attacker_port = addr
                    try:
                        conn.sendall(banner)
                        conn.settimeout(3.0)
                        data = b""
                        try:
                            data = conn.recv(512)
                        except Exception:
                            pass
                    finally:
                        conn.close()
                    self._on_network_hit(port, service, attacker_ip, attacker_port, data)
                except socket.timeout:
                    continue
                except Exception:
                    continue
        except OSError as e:
            log.debug(f"Honeypot port {port} unavailable: {e}")

    def _start_network_honeypots(self):
        for port, banner, service in HONEYPOT_SERVICES:
            t = threading.Thread(
                target=self._serve_honeypot_port,
                args=(port, banner, service),
                name=f"Honeypot-{service}-{port}",
                daemon=True,
            )
            t.start()
            self._servers.append(t)

    # ── Main run ──────────────────────────────────────────────────────────────

    def run(self, event_bus):
        self._event_bus = event_bus
        self._start_file_watcher()
        self._start_network_honeypots()
        log.info(f"HoneypotMesh active: {len(DECOY_FILES)} file decoys + "
                 f"{len(HONEYPOT_SERVICES)} network services")
        while True:
            time.sleep(60)
            # Purge old alerts every hour to re-alert on sustained scanning
            with self._lock:
                if len(self._alerted) > 1000:
                    self._alerted.clear()
