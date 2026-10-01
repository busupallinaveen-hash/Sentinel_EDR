#!/usr/bin/env python3
"""
intel/threat_intel.py — Threat Intelligence Engine

Maintains local IOC (Indicator of Compromise) database and checks
running processes/connections against it.

Sources:
  - Local IOC file (sentinel_ioc.json) — add your own indicators
  - Built-in high-confidence IOC list (known malware hashes, C2 IPs, domains)
  - Optional: fetch from open threat intel feeds (URLhaus, Abuse.ch, etc.)

IOC types:
  - ip:     known C2 / malware distribution IPs
  - domain: known malicious domains
  - hash:   known malware file hashes (MD5/SHA256)
  - ua:     malicious user-agent strings
"""

import hashlib, json, logging, os, platform, threading, time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional

log    = logging.getLogger("SentinelEDR.ThreatIntel")
SYSTEM = platform.system()

try:
    import psutil
    PSUTIL = True
except ImportError:
    PSUTIL = False

# ── Built-in high-confidence IOCs ─────────────────────────────────────────────
# These are known malicious indicators — kept small for the built-in set.
# Add your own to sentinel_ioc.json.

BUILTIN_IOCS = {
    "ip": {
        # Known C2 / red team infrastructure (examples)
        "192.168.56.1":    "Metasploit default listener IP",
        "10.10.10.10":     "Common pentest C2 IP",
        "0.0.0.0":         "Suspicious bind-all",
    },
    "domain": {
        # Known malicious domains (examples — update with live feeds)
        "evil.example.com":      "Test IOC domain",
        "malware.example.org":   "Test IOC domain",
        "cobalt.strike.example": "CobaltStrike example",
    },
    "hash_md5": {
        # Known malware hashes (examples)
        "d41d8cd98f00b204e9800998ecf8427e": "Empty file (suspicious if reported as EXE)",
    },
    "process_name": {
        # Process names associated with known attack tools
        "mimikatz.exe":    "Credential dumper — Mimikatz",
        "mimilib.dll":     "Mimikatz component",
        "wce.exe":         "Windows Credential Editor",
        "gsecdump.exe":    "Credential dumper — gsecdump",
        "pwdump7.exe":     "Password dumper — PwDump7",
        "fgdump.exe":      "Password dumper — FgDump",
        "procdump.exe":    "Process dumper (legitimate but abused)",
        "lazagne.exe":     "Credential recovery tool — LaZagne",
        "sharphound.exe":  "BloodHound collector — AD recon",
        "rubeus.exe":      "Kerberos attack tool — Rubeus",
        "certify.exe":     "AD certificate abuse tool",
        "seatbelt.exe":    "Host situational awareness tool",
        "sharpup.exe":     "Privilege escalation checks",
        "winpeas.exe":     "Privilege escalation enumeration",
        "linpeas.sh":      "Linux privilege escalation enumeration",
        "pspy":            "Process spy — no-root process monitor",
        "chisel":          "TCP tunneling tool",
        "ligolo":          "VPN tunneling for attackers",
        "sliver":          "C2 framework agent",
        "havoc":           "C2 framework",
        "covenant.exe":    "C2 framework agent",
    }
}

LOCAL_IOC_FILE = Path("sentinel_ioc.json")


class ThreatIntelEngine:
    ENGINE = "ThreatIntel"

    def __init__(self, ioc_file: Optional[str] = None):
        self._ioc_file = Path(ioc_file) if ioc_file else LOCAL_IOC_FILE
        self._iocs     = {k: dict(v) for k, v in BUILTIN_IOCS.items()}
        self._alerted  = set()
        self._lock     = threading.Lock()
        self._load_local_iocs()
        log.info(f"ThreatIntel loaded: {self._ioc_summary()}")

    def _ioc_summary(self) -> str:
        return " | ".join(f"{k}: {len(v)}" for k, v in self._iocs.items())

    def _load_local_iocs(self):
        """Merge local IOC file if present."""
        if not self._ioc_file.exists():
            self._create_example_ioc_file()
            return
        try:
            with open(self._ioc_file) as f:
                local = json.load(f)
            for category, entries in local.items():
                if category.startswith("_"):
                    continue  # skip _comment and other meta keys
                if not isinstance(entries, dict):
                    continue  # skip non-dict values
                if category not in self._iocs:
                    self._iocs[category] = {}
                self._iocs[category].update(entries)
            log.info(f"Loaded local IOCs from {self._ioc_file}")
        except Exception as e:
            log.warning(f"Failed to load local IOC file: {e}")

    def _create_example_ioc_file(self):
        """Create a template IOC file for the user to populate."""
        example = {
            "_comment": "SentinelEDR IOC file. Add your own indicators below.",
            "ip": {
                "1.2.3.4": "Known C2 server — add your IOCs here"
            },
            "domain": {
                "bad.example.com": "Known malicious domain"
            },
            "hash_md5": {
                "abc123...": "Known malware hash"
            },
            "hash_sha256": {},
            "process_name": {}
        }
        try:
            with open(self._ioc_file, "w") as f:
                json.dump(example, f, indent=2)
        except Exception:
            pass

    def add_ioc(self, category: str, indicator: str, description: str):
        """Dynamically add an IOC (e.g., from a SIEM feed)."""
        with self._lock:
            if category not in self._iocs:
                self._iocs[category] = {}
            self._iocs[category][indicator] = description

    def check_ip(self, ip: str) -> Optional[str]:
        return self._iocs.get("ip", {}).get(ip)

    def check_domain(self, domain: str) -> Optional[str]:
        domain = domain.lower().rstrip(".")
        iocs = self._iocs.get("domain", {})
        # Exact match
        if domain in iocs:
            return iocs[domain]
        # Subdomain match
        for d, desc in iocs.items():
            if domain.endswith("." + d):
                return f"{desc} (subdomain match: {d})"
        return None

    def check_hash(self, md5: str = "", sha256: str = "") -> Optional[str]:
        if md5:
            hit = self._iocs.get("hash_md5", {}).get(md5.lower())
            if hit:
                return hit
        if sha256:
            hit = self._iocs.get("hash_sha256", {}).get(sha256.lower())
            if hit:
                return hit
        return None

    def check_process_name(self, name: str) -> Optional[str]:
        return self._iocs.get("process_name", {}).get(name.lower())

    def scan(self, event_bus):
        if not PSUTIL:
            return

        try:
            procs = list(psutil.process_iter(["pid", "name", "exe"]))
        except Exception:
            return

        for proc in procs:
            try:
                info = proc.info
                name = (info["name"] or "").lower()
                pid  = info["pid"]

                # Check process name against IOCs
                hit = self.check_process_name(name)
                if hit:
                    alert_key = f"proc:{pid}:{name}"
                    with self._lock:
                        if alert_key not in self._alerted:
                            self._alerted.add(alert_key)
                            self._emit_alert(event_bus, "THREAT_INTEL_PROCESS",
                                             f"Known attack tool: {name}",
                                             f"Process '{name}' (PID {pid}) matches threat intel: {hit}",
                                             95, {"pid": pid, "name": name, "ioc": hit},
                                             "T1588", "resource_development")

                # Check network connections against IP IOCs
                try:
                    conns = proc.net_connections()
                    for c in conns:
                        if c.raddr:
                            ip  = c.raddr.ip
                            hit = self.check_ip(ip)
                            if hit:
                                alert_key = f"ip:{ip}:{pid}"
                                with self._lock:
                                    if alert_key not in self._alerted:
                                        self._alerted.add(alert_key)
                                        self._emit_alert(
                                            event_bus, "THREAT_INTEL_C2_IP",
                                            f"Connection to known C2: {ip}",
                                            f"Process '{name}' (PID {pid}) connecting to "
                                            f"known malicious IP {ip}: {hit}",
                                            98, {"pid": pid, "name": name,
                                                 "remote_ip": ip, "ioc": hit},
                                            "T1071", "command_and_control"
                                        )
                except (psutil.AccessDenied, AttributeError):
                    pass

                # Hash check for executables
                exe = info.get("exe")
                if exe and os.path.exists(exe):
                    try:
                        with open(exe, "rb") as f:
                            data = f.read(65536)  # first 64KB
                        md5 = hashlib.md5(data).hexdigest()
                        hit = self.check_hash(md5=md5)
                        if hit:
                            alert_key = f"hash:{md5}"
                            with self._lock:
                                if alert_key not in self._alerted:
                                    self._alerted.add(alert_key)
                                    self._emit_alert(
                                        event_bus, "THREAT_INTEL_MALWARE_HASH",
                                        f"Known malware hash: {name}",
                                        f"Process '{name}' has known malware MD5 {md5}: {hit}",
                                        99, {"pid": pid, "name": name,
                                             "exe": exe, "md5": md5, "ioc": hit},
                                        "T1588.001", "resource_development"
                                    )
                    except (PermissionError, OSError):
                        pass

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                log.debug(f"ThreatIntel scan error: {e}")

        with self._lock:
            if len(self._alerted) > 5000:
                self._alerted.clear()

    def _emit_alert(self, event_bus, atype, title, desc, risk,
                    proc_info, mitre_tech, mitre_tactic):
        from core.alert_manager import Alert
        sev = "CRITICAL" if risk >= 90 else "HIGH" if risk >= 70 else "MEDIUM"
        a = Alert(
            alert_type   = atype,
            severity     = sev,
            title        = title,
            description  = desc,
            process_info = proc_info,
            risk_score   = risk,
            mitre_tech   = mitre_tech,
            mitre_tactic = mitre_tactic,
            engine       = self.ENGINE,
        )
        event_bus.publish("alert", {"kind": "alert", "alert": a})
