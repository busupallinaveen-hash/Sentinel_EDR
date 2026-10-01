#!/usr/bin/env python3
"""
detection/behavioral/ancestry.py — Process Ancestry Graph Engine

Tracks parent→child process chains. Detects suspicious spawns like:
  - word.exe → cmd.exe
  - browser → powershell → curl | bash
  - sshd → python3 → nc (reverse shell)
  - Office apps spawning scripting engines (macro execution)

Source: NeuralGuard ProcessAncestryGraph, extended with IDPS chain patterns.
"""

import logging, platform, threading, time
from collections import defaultdict

log    = logging.getLogger("SentinelEDR.ProcessAncestry")
SYSTEM = platform.system()

try:
    import psutil
    PSUTIL = True
except ImportError:
    PSUTIL = False

# ── Suspicious parent → child patterns ────────────────────────────────────────
# Format: {parent_name: [(child_pattern, severity, mitre_tech, description)]}

SUSPICIOUS_CHAINS = {
    # Office macros spawning shells
    "winword.exe":   [("cmd.exe",        "HIGH",     "T1566.001", "Word spawned CMD — macro execution"),
                      ("powershell.exe",  "CRITICAL", "T1566.001", "Word spawned PowerShell — macro"),
                      ("wscript.exe",     "HIGH",     "T1566.001", "Word spawned WScript"),
                      ("mshta.exe",       "CRITICAL", "T1218.005", "Word spawned MSHTA")],
    "excel.exe":     [("cmd.exe",        "HIGH",     "T1566.001", "Excel spawned CMD — macro execution"),
                      ("powershell.exe",  "CRITICAL", "T1566.001", "Excel spawned PowerShell")],
    "outlook.exe":   [("cmd.exe",        "HIGH",     "T1566.001", "Outlook spawned CMD"),
                      ("powershell.exe",  "CRITICAL", "T1566.001", "Outlook spawned PowerShell")],
    # Browser to shell
    "chrome.exe":    [("cmd.exe",        "MEDIUM",   "T1059",     "Chrome spawned CMD"),
                      ("powershell.exe",  "HIGH",     "T1059.001", "Chrome spawned PowerShell")],
    "firefox.exe":   [("cmd.exe",        "MEDIUM",   "T1059",     "Firefox spawned CMD"),
                      ("powershell.exe",  "HIGH",     "T1059.001", "Firefox spawned PowerShell")],
    # Web servers spawning shells (webshell indicator)
    "apache2":       [("bash",           "CRITICAL", "T1505.003", "Apache spawned bash — webshell?"),
                      ("sh",             "CRITICAL", "T1505.003", "Apache spawned sh — webshell?"),
                      ("python3",        "HIGH",     "T1505.003", "Apache spawned Python")],
    "nginx":         [("bash",           "CRITICAL", "T1505.003", "Nginx spawned bash — webshell?"),
                      ("sh",             "CRITICAL", "T1505.003", "Nginx spawned sh")],
    "httpd":         [("bash",           "CRITICAL", "T1505.003", "httpd spawned bash — webshell?")],
    # SSH lateral movement
    "sshd":          [("bash",           "MEDIUM",   "T1021.004", "SSH session shell (monitor)"),
                      ("python3",        "HIGH",     "T1021.004", "SSH spawned Python"),
                      ("nc",             "CRITICAL", "T1059",     "SSH spawned netcat — C2?"),
                      ("ncat",           "CRITICAL", "T1059",     "SSH spawned ncat — C2?")],
    # LOLBin chains
    "mshta.exe":     [("powershell.exe", "CRITICAL", "T1218.005", "MSHTA spawned PowerShell"),
                      ("cmd.exe",        "HIGH",     "T1218.005", "MSHTA spawned CMD")],
    "wmic.exe":      [("cmd.exe",        "HIGH",     "T1047",     "WMIC spawned CMD — WMI abuse"),
                      ("powershell.exe", "CRITICAL", "T1047",     "WMIC spawned PowerShell")],
    "rundll32.exe":  [("cmd.exe",        "HIGH",     "T1218.011", "Rundll32 spawned CMD"),
                      ("powershell.exe", "CRITICAL", "T1218.011", "Rundll32 spawned PowerShell")],
    "regsvr32.exe":  [("cmd.exe",        "HIGH",     "T1218.010", "Regsvr32 spawned CMD — Squiblydoo"),
                      ("powershell.exe", "CRITICAL", "T1218.010", "Regsvr32 spawned PowerShell")],
    # Linux suspicious chains
    "cron":          [("bash",           "MEDIUM",   "T1053.003", "Cron spawned bash"),
                      ("python3",        "MEDIUM",   "T1053.003", "Cron spawned Python"),
                      ("curl",           "HIGH",     "T1053.003", "Cron spawned curl — dropper?"),
                      ("wget",           "HIGH",     "T1053.003", "Cron spawned wget — dropper?")],
    "python3":       [("nc",             "CRITICAL", "T1059",     "Python spawned netcat — reverse shell"),
                      ("bash",           "HIGH",     "T1059",     "Python spawned bash")],
    "bash":          [("nc",             "CRITICAL", "T1059.004", "Bash spawned netcat — reverse shell"),
                      ("ncat",           "CRITICAL", "T1059.004", "Bash spawned ncat"),
                      ("python3",        "MEDIUM",   "T1059.004", "Bash spawned Python")],
}

# ── LOLBin argument patterns ───────────────────────────────────────────────────
LOLBIN_PATTERNS = [
    ("base64 -d",          "CRITICAL", "T1027",     "Base64 decode pipe — obfuscated payload"),
    ("base64 -D",          "CRITICAL", "T1027",     "Base64 decode pipe (macOS)"),
    ("-EncodedCommand",    "CRITICAL", "T1059.001", "PowerShell encoded command"),
    ("-enc ",              "HIGH",     "T1059.001", "PowerShell short-form encoded command"),
    ("IEX(",               "CRITICAL", "T1059.001", "PowerShell IEX — remote code execution"),
    ("Invoke-Expression",  "CRITICAL", "T1059.001", "PowerShell Invoke-Expression"),
    ("DownloadString",     "HIGH",     "T1105",     "PowerShell download cradle"),
    ("DownloadFile",       "HIGH",     "T1105",     "PowerShell DownloadFile"),
    ("/dev/tcp/",          "CRITICAL", "T1059.004", "Bash /dev/tcp reverse shell"),
    ("curl | bash",        "CRITICAL", "T1059",     "curl pipe to bash — dropper"),
    ("curl|bash",          "CRITICAL", "T1059",     "curl pipe to bash — dropper"),
    ("wget | bash",        "CRITICAL", "T1059",     "wget pipe to bash — dropper"),
    ("wget|bash",          "CRITICAL", "T1059",     "wget pipe to bash — dropper"),
    ("chmod +x",           "MEDIUM",   "T1222",     "chmod +x on downloaded file"),
    ("-NoProfile -NonI",   "HIGH",     "T1059.001", "PowerShell stealth flags"),
    ("certutil -decode",   "HIGH",     "T1140",     "certutil decode — LOLBin"),
    ("certutil -urlcache", "HIGH",     "T1105",     "certutil URL download"),
    ("regsvr32 /s /u",     "HIGH",     "T1218.010", "Regsvr32 Squiblydoo"),
]


class ProcessAncestryEngine:
    ENGINE = "ProcessAncestry"

    def __init__(self):
        self._seen_pairs = set()  # suppress repeated alerts for same pair
        self._lock       = threading.Lock()

    def scan(self, event_bus):
        if not PSUTIL:
            return
        try:
            procs = {p.pid: p for p in psutil.process_iter(
                ["pid", "name", "ppid", "cmdline", "username"]
            )}
        except Exception:
            return

        for pid, proc in procs.items():
            try:
                info   = proc.info
                name   = (info["name"] or "").lower()
                ppid   = info["ppid"]
                cmdline = " ".join(info["cmdline"] or [])
                parent = procs.get(ppid)
                pname  = (parent.info["name"] or "").lower() if parent else ""

                # ── Parent-child chain check ──────────────────────────────────
                if pname in SUSPICIOUS_CHAINS:
                    for child_pattern, severity, mitre_tech, desc in SUSPICIOUS_CHAINS[pname]:
                        if name == child_pattern or name.startswith(child_pattern.rstrip(".exe")):
                            pair_key = (pname, name, ppid, pid)
                            with self._lock:
                                if pair_key in self._seen_pairs:
                                    continue
                                self._seen_pairs.add(pair_key)

                            from core.alert_manager import Alert
                            a = Alert(
                                alert_type   = "SUSPICIOUS_PROCESS_CHAIN",
                                severity     = severity,
                                title        = f"Suspicious chain: {pname} → {name}",
                                description  = f"{desc} | PID {ppid} → {pid}",
                                process_info = {
                                    "pid": pid, "name": name,
                                    "parent": pname, "ppid": ppid,
                                    "cmdline": cmdline[:200],
                                },
                                risk_score   = {"CRITICAL":85,"HIGH":65,"MEDIUM":45,"LOW":25}.get(severity,50),
                                mitre_tactic = "execution",
                                mitre_tech   = mitre_tech,
                                engine       = self.ENGINE,
                            )
                            event_bus.publish("alert", {"kind": "alert", "alert": a})

                # ── LOLBin argument check ─────────────────────────────────────
                if cmdline:
                    for pattern, severity, mitre_tech, desc in LOLBIN_PATTERNS:
                        if pattern.lower() in cmdline.lower():
                            lol_key = (name, pattern, pid)
                            with self._lock:
                                if lol_key in self._seen_pairs:
                                    continue
                                self._seen_pairs.add(lol_key)

                            from core.alert_manager import Alert
                            a = Alert(
                                alert_type   = "LOLBIN_ABUSE",
                                severity     = severity,
                                title        = f"LOLBin pattern: {name}",
                                description  = f"{desc} | cmd: {cmdline[:150]}",
                                process_info = {
                                    "pid": pid, "name": name,
                                    "cmdline": cmdline[:300],
                                    "pattern": pattern,
                                },
                                risk_score   = {"CRITICAL":90,"HIGH":70,"MEDIUM":50,"LOW":30}.get(severity,50),
                                mitre_tactic = "execution",
                                mitre_tech   = mitre_tech,
                                engine       = self.ENGINE,
                            )
                            event_bus.publish("alert", {"kind": "alert", "alert": a})

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                log.debug(f"Ancestry scan error: {e}")

        # Prune old seen pairs to prevent unbounded growth
        with self._lock:
            if len(self._seen_pairs) > 10000:
                self._seen_pairs.clear()
