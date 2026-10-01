#!/usr/bin/env python3
"""
detection/behavioral/chain_engine.py — Behavioral Attack Chain Engine

Detects multi-event attack sequences that neither single-event rules
nor ML can catch alone. Tracks per-host event streams and fires when
known attack patterns complete within a sliding time window.

Built-in patterns (from IDPS behavioral_engine.py):
  BEH-001: Credential dump → Lateral movement
  BEH-002: Download cradle → Execute → C2 connect
  BEH-003: Brute force → Successful logon
  BEH-004: Recon → Persistence → C2 establishment
  BEH-005: Process injection → Network connect

Source: IDPS BehavioralEngine patterns, adapted for SentinelEDR event bus.
"""

import logging, platform, threading, time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

log    = logging.getLogger("SentinelEDR.ChainEngine")
SYSTEM = platform.system()

try:
    import psutil
    PSUTIL = True
except ImportError:
    PSUTIL = False


@dataclass
class PatternStep:
    description: str
    process_names: List[str] = field(default_factory=list)   # any of these
    cmdline_contains: List[str] = field(default_factory=list) # any of these


@dataclass
class AttackChain:
    chain_id:      str
    title:         str
    description:   str
    severity:      str
    steps:         List[PatternStep]
    window_secs:   int  = 300
    mitre_tactic:  str  = ""
    mitre_tech:    str  = ""


# ── Built-in attack chains ─────────────────────────────────────────────────────

CHAINS: List[AttackChain] = [

    AttackChain(
        chain_id     = "BEH-001",
        title        = "Credential dump → Lateral movement",
        description  = "LSASS/credential access followed by network authentication tool — "
                       "classic dump-and-move sequence.",
        severity     = "CRITICAL",
        window_secs  = 300,
        mitre_tactic = "lateral_movement",
        mitre_tech   = "T1003.001",
        steps        = [
            PatternStep("LSASS/credential access",
                        process_names=["lsass.exe"],
                        cmdline_contains=["sekurlsa", "mimikatz", "procdump", "comsvcs"]),
            PatternStep("Lateral movement tool",
                        process_names=["net.exe", "wmic.exe", "psexec.exe", "smbclient"],
                        cmdline_contains=["net use", "psexec", "wmiexec"]),
        ],
    ),

    AttackChain(
        chain_id     = "BEH-002",
        title        = "Download cradle → Execute → C2 connect",
        description  = "Payload downloaded via scripting, new process spawned, "
                       "then outbound network — staged payload execution.",
        severity     = "CRITICAL",
        window_secs  = 180,
        mitre_tactic = "execution",
        mitre_tech   = "T1059.001",
        steps        = [
            PatternStep("Download cradle",
                        process_names=["powershell.exe", "cmd.exe"],
                        cmdline_contains=["IEX", "Invoke-Expression",
                                          "DownloadString", "-EncodedCommand"]),
            PatternStep("Suspicious execution",
                        process_names=["wscript.exe", "cscript.exe", "mshta.exe"],
                        cmdline_contains=["http://", "https://", ".ps1", ".vbs"]),
            PatternStep("Outbound C2",
                        process_names=["nc", "ncat", "netcat", "socat"],
                        cmdline_contains=["-e /bin/bash", "-e cmd.exe", "/dev/tcp/"]),
        ],
    ),

    AttackChain(
        chain_id     = "BEH-003",
        title        = "Recon → Persistence installation",
        description  = "System discovery commands followed by persistence mechanism — "
                       "attacker mapping environment then installing backdoor.",
        severity     = "HIGH",
        window_secs  = 600,
        mitre_tactic = "persistence",
        mitre_tech   = "T1547",
        steps        = [
            PatternStep("System recon",
                        process_names=["whoami", "net.exe", "ipconfig", "ifconfig",
                                       "hostname", "systeminfo", "uname"],
                        cmdline_contains=["whoami", "net user", "net group", "ipconfig",
                                          "ifconfig", "netstat", "ps aux", "systeminfo"]),
            PatternStep("Persistence mechanism",
                        process_names=["schtasks.exe", "reg.exe", "crontab", "systemctl",
                                       "sc.exe", "at.exe"],
                        cmdline_contains=["schtasks /create", "reg add", "crontab -e",
                                          "systemctl enable", "sc create"]),
        ],
    ),

    AttackChain(
        chain_id     = "BEH-004",
        title        = "Process injection → Network connect",
        description  = "Memory injection technique followed by suspicious network — "
                       "injected C2 beacon from legitimate process.",
        severity     = "CRITICAL",
        window_secs  = 60,
        mitre_tactic = "defense_evasion",
        mitre_tech   = "T1055",
        steps        = [
            PatternStep("Injection tool",
                        process_names=["powershell.exe", "rundll32.exe", "regsvr32.exe"],
                        cmdline_contains=["VirtualAlloc", "WriteProcessMemory",
                                          "CreateRemoteThread", "NtCreateThreadEx"]),
            PatternStep("Suspicious network",
                        process_names=["svchost.exe", "explorer.exe", "notepad.exe"],
                        cmdline_contains=[]),
        ],
    ),

    AttackChain(
        chain_id     = "BEH-005",
        title        = "Defense evasion → Exfiltration",
        description  = "Log clearing or AV disabling followed by data transfer — "
                       "attacker covering tracks before exfil.",
        severity     = "HIGH",
        window_secs  = 300,
        mitre_tactic = "exfiltration",
        mitre_tech   = "T1048",
        steps        = [
            PatternStep("Defense evasion",
                        process_names=["wevtutil.exe", "reg.exe", "sc.exe"],
                        cmdline_contains=["wevtutil cl", "reg delete", "sc stop",
                                          "Set-MpPreference -Disable"]),
            PatternStep("Data transfer",
                        process_names=["curl", "wget", "ftp", "scp", "rclone",
                                       "certutil.exe"],
                        cmdline_contains=["curl -X POST", "wget --post", "ftp -u",
                                          "scp ", "rclone copy"]),
        ],
    ),
]


class ChainTracker:
    """Tracks completion state for one attack chain on one host."""

    def __init__(self, chain: AttackChain):
        self.chain        = chain
        self.step_hits    = [None] * len(chain.steps)  # timestamp of first hit
        self.completed    = False

    def check(self, step_idx: int) -> bool:
        now = time.time()
        self.step_hits[step_idx] = now
        filled = [t for t in self.step_hits if t is not None]
        if len(filled) < len(self.chain.steps):
            return False
        window_ok = (max(filled) - min(filled)) <= self.chain.window_secs
        return window_ok

    def reset_expired(self):
        now = time.time()
        for i, t in enumerate(self.step_hits):
            if t is not None and (now - t) > self.chain.window_secs:
                self.step_hits[i] = None


class BehavioralChainEngine:
    ENGINE = "ChainEngine"

    def __init__(self):
        # {chain_id: ChainTracker}
        self._trackers  = {c.chain_id: ChainTracker(c) for c in CHAINS}
        self._fired     = set()
        self._lock      = threading.Lock()
        self._start_time = time.time()
        self._warmup_secs = 60  # don't fire chain alerts in first 60s (avoid startup FPs)

    def scan(self, event_bus):
        if not PSUTIL:
            return
        # Skip chain detection during warmup — avoids startup false positives
        if time.time() - self._start_time < self._warmup_secs:
            return
        try:
            procs = list(psutil.process_iter(["pid", "name", "cmdline"]))
        except Exception:
            return

        for proc in procs:
            try:
                info    = proc.info
                name    = (info["name"] or "").lower()
                cmdline = " ".join(info["cmdline"] or []).lower()

                for chain in CHAINS:
                    tracker = self._trackers[chain.chain_id]
                    tracker.reset_expired()

                    for i, step in enumerate(chain.steps):
                        has_names  = bool(step.process_names)
                        has_cmds   = bool(step.cmdline_contains)
                        name_match = has_names and any(p.lower() in name for p in step.process_names)
                        cmd_match  = has_cmds  and any(c.lower() in cmdline for c in step.cmdline_contains)
                        # When a step specifies BOTH a process type and suspicious
                        # command-line indicators, both must hold together — e.g.
                        # "powershell.exe" alone is normal; "powershell.exe running
                        # IEX/DownloadString" is not. Requiring only one of the two
                        # (the previous `or`) meant any step naming a common process
                        # (lsass.exe, svchost.exe, or even matching "https://" against
                        # any process's cmdline) would fire on totally ordinary
                        # activity — that's what flagged a normal chrome.exe launch
                        # as "Download cradle -> Execute -> C2 connect". A step with
                        # only one of the two lists populated still falls back to that
                        # single signal (e.g. BEH-004's cmdline-less network step).
                        if has_names and has_cmds:
                            matched = name_match and cmd_match
                        else:
                            matched = name_match or cmd_match
                        if matched:
                            if tracker.check(i):
                                fire_key = f"{chain.chain_id}:{int(time.time()//300)}"
                                with self._lock:
                                    if fire_key in self._fired:
                                        break
                                    self._fired.add(fire_key)

                                from core.alert_manager import Alert
                                a = Alert(
                                    alert_type   = "ATTACK_CHAIN_DETECTED",
                                    severity     = chain.severity,
                                    title        = f"Attack chain: {chain.title}",
                                    description  = chain.description,
                                    process_info = {
                                        "chain_id": chain.chain_id,
                                        "trigger":  name,
                                        "pid":      info["pid"],
                                    },
                                    risk_score   = {
                                        "CRITICAL": 92, "HIGH": 72,
                                        "MEDIUM": 52, "LOW": 32
                                    }.get(chain.severity, 60),
                                    mitre_tactic = chain.mitre_tactic,
                                    mitre_tech   = chain.mitre_tech,
                                    engine       = self.ENGINE,
                                )
                                event_bus.publish("alert", {"kind": "alert", "alert": a})
                                tracker.step_hits = [None] * len(chain.steps)
                                break

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                log.debug(f"Chain scan error: {e}")
