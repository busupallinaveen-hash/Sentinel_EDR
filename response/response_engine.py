#!/usr/bin/env python3
"""
response/response_engine.py — Active Response Engine

Automated defensive responses triggered by alert severity and type.
Source: NeuralGuard ResponseEngine, extended with IDPS SOAR-style playbooks.

Response actions:
  KILL_PROCESS      — terminate malicious process
  SUSPEND_PROCESS   — suspend for investigation
  QUARANTINE_FILE   — move file to encrypted vault
  BLOCK_IP          — add firewall rule (iptables/netsh/pfctl)
  COLLECT_FORENSICS — snapshot process + network state
  ISOLATE_HOST      — block all traffic except loopback (last resort,
                       opt-in via response.isolate_on_ransomware; undo with
                       `sentinel.py --restore-network`)
  ALERT_ONLY        — log + notify, no automated action

Response rules (priority order):
  CRITICAL honeypot hit        → KILL + BLOCK_IP (if attacker IP known) + COLLECT_FORENSICS
  CRITICAL ransomware entropy  → KILL + QUARANTINE + COLLECT_FORENSICS
  CRITICAL ransomware velocity → same, + ISOLATE_HOST if opted in
  CRITICAL attack chain        → KILL + BLOCK_IP (if IP known) + COLLECT_FORENSICS
  C2 beaconing / exfil domain  → BLOCK_IP + COLLECT_FORENSICS
  HIGH sigma/behavioral        → COLLECT_FORENSICS + ALERT
  MEDIUM                       → ALERT_ONLY
"""

import hashlib, json, logging, os, platform, shutil, subprocess, threading, time, zipfile
from datetime import datetime
from pathlib import Path
from typing import Optional

log    = logging.getLogger("SentinelEDR.Response")
SYSTEM = platform.system()

try:
    import psutil
    PSUTIL = True
except ImportError:
    PSUTIL = False

PROTECTED_PIDS  = {0, 1}
PROTECTED_NAMES = {
    "systemd", "init", "kernel", "kthreadd", "launchd",
    "winlogon", "csrss", "smss", "lsass", "services",
    "explorer", "svchost", "sentinel",
}


class ResponseResult:
    def __init__(self, action: str, success: bool, message: str = "", details: dict = None):
        self.action    = action
        self.success   = success
        self.message   = message
        self.details   = details or {}
        self.timestamp = datetime.now().isoformat()

    def __str__(self):
        status = "✅" if self.success else "❌"
        return f"{status} [{self.action}] {self.message}"

    def to_dict(self):
        return {"action": self.action, "success": self.success,
                "message": self.message, "details": self.details,
                "timestamp": self.timestamp}


class ResponseEngine:
    def __init__(self, paths: dict, dry_run: bool = False, auto_respond: bool = True,
                 isolate_on_ransomware: bool = False,
                 kill_threshold: int = 85, block_ip_threshold: int = 75):
        self._paths        = paths
        self._dry_run      = dry_run
        self._auto_respond = auto_respond
        # Host isolation is the most destructive action this engine can take
        # (it can cut off your own remote access), so it's opt-in via config
        # rather than firing automatically just because auto_respond is on.
        self._isolate_on_ransomware = isolate_on_ransomware
        self._kill_threshold     = kill_threshold
        self._block_ip_threshold = block_ip_threshold
        self._blocked_ips   = set()
        self._killed_pids   = set()
        self._isolated      = False
        self._isolate_rules = []   # exact rule specs added, so restore can undo precisely
        self._lock          = threading.Lock()
        self._response_log  = []

        os.makedirs(str(paths.get("quarantine", "/tmp/sentinel_q")), exist_ok=True)
        os.makedirs(str(paths.get("forensics",  "/tmp/sentinel_f")), exist_ok=True)

        if dry_run:
            log.info("ResponseEngine in DRY-RUN mode — no automated actions")
        else:
            log.info("ResponseEngine active — automated responses ENABLED")

    # ── Alert handler (EventBus callback) ─────────────────────────────────────

    def handle_alert(self, event: dict):
        alert = event.get("alert")
        if alert is None:
            return
        if hasattr(alert, "to_dict"):
            d = alert.to_dict()
        else:
            d = alert

        atype    = d.get("type", "")
        severity = d.get("severity", "LOW")
        proc     = d.get("process", {})
        pid      = proc.get("pid")
        risk     = d.get("risk_score", 0)

        if self._dry_run:
            log.info(f"[DRY-RUN] Would respond to: {atype} sev={severity} risk={risk}")
            return

        # ── Response playbooks ────────────────────────────────────────────────
        if atype in ("HONEYPOT_FILE_ACCESS", "HONEYPOT_NETWORK_HIT"):
            if pid:
                self._kill_process(pid, proc.get("name", ""), reason=atype)
            self._collect_forensics(pid, proc.get("name", ""), atype)
            attacker_ip = proc.get("attacker_ip") or proc.get("remote_ip")
            if attacker_ip:
                self._block_ip(attacker_ip, reason=atype)

        elif atype in ("RANSOMWARE_ENTROPY", "RANSOMWARE_VELOCITY"):
            if pid:
                self._kill_process(pid, proc.get("name", ""), reason=atype)
            path = proc.get("path")
            if path:
                self._quarantine_file(path, reason=atype)
            self._collect_forensics(pid, proc.get("name", ""), atype)
            # Host isolation is the "stop mass encryption from spreading over
            # the network / to shares" last resort. Scoped deliberately narrow:
            # only the velocity signal (many files written per minute — active,
            # ongoing encryption), never a single high-entropy write alone,
            # and only when explicitly opted in via config. This is off by
            # default; enable response.isolate_on_ransomware in sentinel.yaml
            # only once you trust the detection's false-positive rate on your
            # own machine.
            if atype == "RANSOMWARE_VELOCITY" and self._isolate_on_ransomware:
                self._isolate_host(reason=atype)

        elif atype in ("C2_BEACONING", "DLP_EXFIL_DOMAIN"):
            # DomainMonitor alerts carry the remote IP directly, not a PID —
            # these were previously falling through to the generic HIGH-severity
            # branch below (forensics only), so the "auto-block IPs" playbook
            # never actually ran for the two alert types most likely to name
            # a real attacker IP.
            remote_ip = proc.get("remote_ip")
            if remote_ip:
                self._block_ip(remote_ip, reason=atype)
            self._collect_forensics(pid, proc.get("name", ""), atype)

        elif atype == "ATTACK_CHAIN_DETECTED" and severity == "CRITICAL":
            if pid:
                self._kill_process(pid, proc.get("name", ""), reason=atype)
            # Docstring promises BLOCK_IP for a critical attack chain; only
            # actually do it when the chain alert carries a real remote IP
            # (chain_engine doesn't always have one — e.g. a purely local
            # execution chain has nothing to block).
            remote_ip = proc.get("remote_ip") or proc.get("attacker_ip")
            if remote_ip:
                self._block_ip(remote_ip, reason=atype)
            self._collect_forensics(pid, proc.get("name", ""), atype)

        elif severity == "CRITICAL" and risk >= self._kill_threshold:
            # Previously only two specific legacy rule IDs (SIG-051, SIG-020)
            # actually got killed here — every other CRITICAL alert, including
            # newer high-confidence rules like SIG-080 (Office spawning a
            # shell) and SIG-083 (AMSI bypass), only got forensics collected.
            # That contradicted this engine's own docstring ("CRITICAL → KILL
            # + ...") and left kill_threshold in sentinel.yaml unused. Any
            # sufficiently severe CRITICAL alert with a real PID is now
            # killed, not just an arbitrary two-rule allowlist.
            self._collect_forensics(pid, proc.get("name", ""), atype)
            if pid:
                self._kill_process(pid, proc.get("name", ""), reason=atype)
            remote_ip = proc.get("remote_ip") or proc.get("attacker_ip")
            if remote_ip and risk >= self._block_ip_threshold:
                self._block_ip(remote_ip, reason=atype)

        elif severity == "HIGH":
            self._collect_forensics(pid, proc.get("name", ""), atype)
            remote_ip = proc.get("remote_ip") or proc.get("attacker_ip")
            if remote_ip and risk >= self._block_ip_threshold:
                self._block_ip(remote_ip, reason=atype)

    # ── Actions ───────────────────────────────────────────────────────────────

    def _kill_process(self, pid: int, name: str = "", reason: str = "") -> ResponseResult:
        if not PSUTIL or not pid:
            return ResponseResult("KILL", False, "psutil unavailable or no pid")
        if pid in PROTECTED_PIDS or pid == os.getpid():
            return ResponseResult("KILL", False, f"Protected PID {pid}")
        if name.lower() in PROTECTED_NAMES:
            return ResponseResult("KILL", False, f"Protected process: {name}")
        with self._lock:
            if pid in self._killed_pids:
                return ResponseResult("KILL", True, f"PID {pid} already killed")
        try:
            p = psutil.Process(pid)
            p.kill()
            with self._lock:
                self._killed_pids.add(pid)
            msg = f"Killed '{p.name()}' PID {pid} — {reason}"
            log.warning(f"[RESPONSE] {msg}")
            r = ResponseResult("KILL_PROCESS", True, msg, {"pid": pid, "name": name})
            self._log_response(r)
            return r
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            return ResponseResult("KILL_PROCESS", False, str(e))

    def _block_ip(self, ip: str, reason: str = "") -> ResponseResult:
        with self._lock:
            if ip in self._blocked_ips:
                return ResponseResult("BLOCK_IP", True, f"{ip} already blocked")
        try:
            if SYSTEM == "Linux":
                subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                               check=True, capture_output=True, timeout=5)
                subprocess.run(["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"],
                               check=True, capture_output=True, timeout=5)
            elif SYSTEM == "Windows":
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule",
                     f"name=SentinelBlock_{ip}", "dir=in", "action=block",
                     f"remoteip={ip}"],
                    check=True, capture_output=True, timeout=5
                )
            elif SYSTEM == "Darwin":
                subprocess.run(["pfctl", "-t", "sentinel_block", "-T", "add", ip],
                               check=True, capture_output=True, timeout=5)

            with self._lock:
                self._blocked_ips.add(ip)
            msg = f"Blocked IP {ip} — {reason}"
            log.warning(f"[RESPONSE] {msg}")
            r = ResponseResult("BLOCK_IP", True, msg, {"ip": ip})
            self._log_response(r)
            return r
        except Exception as e:
            log.warning(f"[RESPONSE] Block IP {ip} failed: {e} (may need root)")
            return ResponseResult("BLOCK_IP", False, f"Failed: {e}")

    def _isolate_host(self, reason: str = "") -> ResponseResult:
        """
        Last-resort action: block all inbound/outbound network traffic except
        loopback, so an active ransomware/lateral-movement incident can't
        spread further while it's investigated. Deliberately reversible —
        every rule this adds is tracked in self._isolate_rules and removed
        exactly by _restore_network(), rather than changing firewall default
        policy (which is much harder to safely undo if something goes wrong).

        This does NOT block localhost, so the SentinelEDR dashboard on
        127.0.0.1 stays reachable even while the host is isolated.
        """
        with self._lock:
            if self._isolated:
                return ResponseResult("ISOLATE_HOST", True, "Host already isolated")

        try:
            rules_added = []
            if SYSTEM == "Linux":
                cmds = [
                    ["iptables", "-I", "OUTPUT", "1", "-o", "lo", "-j", "ACCEPT"],
                    ["iptables", "-I", "INPUT",  "1", "-i", "lo", "-j", "ACCEPT"],
                    ["iptables", "-I", "OUTPUT", "2", "-j", "DROP"],
                    ["iptables", "-I", "INPUT",  "2", "-j", "DROP"],
                ]
                for c in cmds:
                    subprocess.run(c, check=True, capture_output=True, timeout=5)
                    rules_added.append(c)

            elif SYSTEM == "Windows":
                cmds = [
                    ["netsh", "advfirewall", "firewall", "add", "rule",
                     "name=SentinelIsolate_Out", "dir=out", "action=block", "enable=yes"],
                    ["netsh", "advfirewall", "firewall", "add", "rule",
                     "name=SentinelIsolate_In",  "dir=in",  "action=block", "enable=yes"],
                ]
                for c in cmds:
                    subprocess.run(c, check=True, capture_output=True, timeout=5)
                rules_added = ["SentinelIsolate_Out", "SentinelIsolate_In"]

            elif SYSTEM == "Darwin":
                subprocess.run(
                    ["bash", "-c", 'echo "block drop all\\npass on lo0 all" | '
                                   "pfctl -a sentinel_isolate -f -"],
                    check=True, capture_output=True, timeout=5)
                subprocess.run(["pfctl", "-e"], capture_output=True, timeout=5)
                rules_added = ["anchor:sentinel_isolate"]

            with self._lock:
                self._isolated = True
                self._isolate_rules = rules_added
            msg = f"Host network isolated (loopback still open) — {reason}"
            log.critical(f"[RESPONSE] {msg}")
            r = ResponseResult("ISOLATE_HOST", True, msg, {"rules": rules_added})
            self._log_response(r)
            return r
        except Exception as e:
            log.warning(f"[RESPONSE] Isolate host failed: {e} (may need admin/root)")
            return ResponseResult("ISOLATE_HOST", False, f"Failed: {e}")

    def _restore_network(self) -> ResponseResult:
        """Undo _isolate_host exactly — removes only the rules it added."""
        with self._lock:
            if not self._isolated:
                return ResponseResult("RESTORE_NETWORK", True, "Host was not isolated")
            rules = list(self._isolate_rules)

        try:
            if SYSTEM == "Linux":
                for c in rules:
                    undo = c.copy()
                    undo[1] = "-D"          # -I insert -> -D delete, same rule spec
                    undo.pop(2)             # drop the numeric insert position
                    subprocess.run(undo, capture_output=True, timeout=5)
            elif SYSTEM == "Windows":
                for name in rules:
                    subprocess.run(
                        ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"],
                        capture_output=True, timeout=5)
            elif SYSTEM == "Darwin":
                subprocess.run(["pfctl", "-a", "sentinel_isolate", "-F", "all"],
                                capture_output=True, timeout=5)

            with self._lock:
                self._isolated = False
                self._isolate_rules = []
            msg = "Network isolation lifted"
            log.warning(f"[RESPONSE] {msg}")
            r = ResponseResult("RESTORE_NETWORK", True, msg)
            self._log_response(r)
            return r
        except Exception as e:
            return ResponseResult("RESTORE_NETWORK", False, f"Failed: {e}")

    def _quarantine_file(self, path: str, reason: str = "") -> ResponseResult:
        q_dir = str(self._paths.get("quarantine", "/tmp/sentinel_q"))
        if not os.path.exists(path):
            return ResponseResult("QUARANTINE", False, f"File not found: {path}")
        try:
            with open(path, "rb") as f:
                data = f.read()
            md5 = hashlib.md5(data).hexdigest()
            sha = hashlib.sha256(data).hexdigest()
            qname = f"QRN_{md5[:16]}_{int(time.time())}.vault"
            qpath = os.path.join(q_dir, qname)
            # XOR-obfuscate to prevent accidental execution
            key = b"SentinelEDRVaultKey2025"
            obf = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
            with open(qpath, "wb") as f:
                f.write(obf)
            # Write manifest
            manifest = {"original": path, "vault_file": qname,
                        "md5": md5, "sha256": sha, "reason": reason,
                        "timestamp": datetime.now().isoformat()}
            with open(qpath + ".json", "w") as f:
                json.dump(manifest, f, indent=2)
            os.remove(path)
            msg = f"Quarantined: {os.path.basename(path)} → {qname}"
            log.warning(f"[RESPONSE] {msg}")
            r = ResponseResult("QUARANTINE_FILE", True, msg, manifest)
            self._log_response(r)
            return r
        except Exception as e:
            return ResponseResult("QUARANTINE_FILE", False, str(e))

    def _collect_forensics(self, pid: Optional[int], name: str = "",
                           trigger: str = "") -> ResponseResult:
        f_dir = str(self._paths.get("forensics", "/tmp/sentinel_f"))
        ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = f"forensics_{name or 'system'}_{ts}.zip"
        fpath = os.path.join(f_dir, fname)

        try:
            snapshot = {
                "trigger":   trigger,
                "timestamp": datetime.now().isoformat(),
                "pid":       pid,
                "process":   name,
            }

            if PSUTIL and pid:
                try:
                    p = psutil.Process(pid)
                    snapshot["process_detail"] = {
                        "name":    p.name(),
                        "exe":     p.exe(),
                        "cmdline": p.cmdline(),
                        "cwd":     p.cwd(),
                        "status":  p.status(),
                        "create_time": p.create_time(),
                        "cpu_pct": p.cpu_percent(interval=0.1),
                        "mem_mb":  p.memory_info().rss / 1048576,
                        "threads": p.num_threads(),
                        "connections": [
                            {"laddr": str(c.laddr), "raddr": str(c.raddr),
                             "status": c.status}
                            for c in p.net_connections()
                        ],
                        "open_files": [f.path for f in p.open_files()[:20]],
                        "environ":    dict(list(p.environ().items())[:30]),
                    }
                except Exception as e:
                    snapshot["process_error"] = str(e)

            if PSUTIL:
                try:
                    snapshot["network_connections"] = [
                        {"pid": c.pid, "laddr": str(c.laddr),
                         "raddr": str(c.raddr), "status": c.status}
                        for c in psutil.net_connections()[:50]
                    ]
                    snapshot["running_processes"] = [
                        {"pid": p.pid, "name": p.name(), "cmdline": p.cmdline()[:3]}
                        for p in psutil.process_iter(["pid", "name", "cmdline"])
                    ][:100]
                except Exception:
                    pass

            with zipfile.ZipFile(fpath, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("snapshot.json", json.dumps(snapshot, indent=2, default=str))

            msg = f"Forensics collected: {fname}"
            log.info(f"[RESPONSE] {msg}")
            r = ResponseResult("COLLECT_FORENSICS", True, msg, {"path": fpath})
            self._log_response(r)
            return r
        except Exception as e:
            return ResponseResult("COLLECT_FORENSICS", False, str(e))

    def _log_response(self, result: ResponseResult):
        with self._lock:
            self._response_log.append(result.to_dict())
            if len(self._response_log) > 500:
                self._response_log = self._response_log[-500:]

    def get_response_log(self) -> list:
        with self._lock:
            return list(self._response_log)
