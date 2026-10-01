#!/usr/bin/env python3
"""
detection/sigma/sigma_engine.py — Sigma Rules Detection Engine

Pattern-based detection using Sigma-style rules applied to running processes.
No external deps — pure Python process inspection.

Covers 38+ high-signal MITRE ATT&CK techniques, spanning Initial Access
through Collection.

Source: IDPS sigma_engine.py rules, ported to SentinelEDR process scanner.
"""

import logging, platform, threading, time
from dataclasses import dataclass, field
from typing import List, Optional

log    = logging.getLogger("SentinelEDR.Sigma")
SYSTEM = platform.system()

try:
    import psutil
    PSUTIL = True
except ImportError:
    PSUTIL = False


@dataclass
class SigmaRule:
    rule_id:     str
    title:       str
    description: str
    severity:    str
    mitre_tech:  str
    mitre_tactic:str
    # Match conditions — all non-empty lists must have at least one match
    process_name_any:  List[str] = field(default_factory=list)  # process name contains any
    cmdline_any:       List[str] = field(default_factory=list)   # cmdline contains any
    cmdline_all:       List[str] = field(default_factory=list)   # cmdline contains ALL
    parent_name_any:   List[str] = field(default_factory=list)   # parent name contains any
    risk_score:        int       = 60


SIGMA_RULES: List[SigmaRule] = [

    # ── Execution ──────────────────────────────────────────────────────────────
    SigmaRule("SIG-001", "PowerShell encoded command execution",
              "PowerShell launched with EncodedCommand flag — obfuscated payload.",
              "HIGH", "T1059.001", "execution",
              process_name_any=["powershell", "pwsh"],
              cmdline_any=["-EncodedCommand", "-enc ", "-e ", "-ec "], risk_score=75),

    SigmaRule("SIG-002", "PowerShell download cradle",
              "PowerShell downloading and executing remote content.",
              "CRITICAL", "T1059.001", "execution",
              process_name_any=["powershell", "pwsh"],
              cmdline_any=["DownloadString", "DownloadFile", "WebClient", "Invoke-WebRequest",
                           "IWR ", "curl -s", "wget "], risk_score=90),

    SigmaRule("SIG-003", "MSHTA execution",
              "MSHTA executing script — Living off the Land.",
              "HIGH", "T1218.005", "defense_evasion",
              process_name_any=["mshta.exe"],
              cmdline_any=["javascript:", "vbscript:", "http://", "https://"], risk_score=80),

    SigmaRule("SIG-004", "Regsvr32 Squiblydoo",
              "Regsvr32 loading a remote scriptlet — AppLocker bypass.",
              "HIGH", "T1218.010", "defense_evasion",
              process_name_any=["regsvr32.exe"],
              cmdline_any=["/s", "/u", "scrobj.dll", "http://"], risk_score=80),

    SigmaRule("SIG-005", "Certutil decode",
              "Certutil used to decode base64 — LOLBin dropper technique.",
              "HIGH", "T1140", "defense_evasion",
              process_name_any=["certutil.exe"],
              cmdline_any=["-decode", "-urlcache", "-f http"], risk_score=75),

    SigmaRule("SIG-006", "Rundll32 executing DLL from temp",
              "Rundll32 loading DLL from temp/appdata — dropper execution.",
              "HIGH", "T1218.011", "defense_evasion",
              process_name_any=["rundll32.exe"],
              cmdline_any=["\\temp\\", "\\appdata\\", "\\programdata\\", "javascript:"], risk_score=75),

    SigmaRule("SIG-007", "WMI spawning process",
              "WMI used to spawn a process — lateral movement or persistence.",
              "HIGH", "T1047", "execution",
              process_name_any=["wmiprvse.exe"],
              cmdline_any=["powershell", "cmd.exe", "cscript", "wscript", "mshta"], risk_score=80),

    # ── Persistence ────────────────────────────────────────────────────────────
    SigmaRule("SIG-010", "Scheduled task creation",
              "Schtasks creating new task — persistence mechanism.",
              "MEDIUM", "T1053.005", "persistence",
              process_name_any=["schtasks.exe"],
              cmdline_any=["/create", "/sc", "/tr", "/tn"], risk_score=55),

    SigmaRule("SIG-011", "Registry run key modification",
              "Reg.exe modifying startup run key — persistence.",
              "HIGH", "T1547.001", "persistence",
              process_name_any=["reg.exe"],
              cmdline_any=["\\CurrentVersion\\Run", "\\CurrentVersion\\RunOnce",
                           "\\Winlogon", "\\Image File Execution"], risk_score=75),

    SigmaRule("SIG-012", "Service installation",
              "SC.exe creating a new service — persistence or privilege escalation.",
              "MEDIUM", "T1543.003", "persistence",
              process_name_any=["sc.exe"],
              cmdline_any=["create", "config", "binpath="], risk_score=55),

    SigmaRule("SIG-013", "Startup folder file drop",
              "File written to startup folder — persistence.",
              "HIGH", "T1547.001", "persistence",
              process_name_any=["cmd.exe", "powershell.exe", "explorer.exe"],
              cmdline_any=["\\Startup\\", "\\Start Menu\\Programs\\Startup"], risk_score=70),

    # ── Credential Access ──────────────────────────────────────────────────────
    SigmaRule("SIG-020", "LSASS memory access",
              "Process accessing LSASS memory — credential dumping attempt.",
              "CRITICAL", "T1003.001", "credential_access",
              cmdline_any=["lsass", "procdump", "comsvcs.dll MiniDump",
                           "sekurlsa", "mimikatz"], risk_score=95),

    SigmaRule("SIG-021", "SAM database access",
              "Attempt to access SAM/NTDS — credential database theft.",
              "CRITICAL", "T1003.002", "credential_access",
              cmdline_any=["\\sam", "\\ntds.dit", "\\system32\\config\\sam",
                           "reg save hklm\\sam"], risk_score=95),

    SigmaRule("SIG-022", "Password file access on Linux",
              "Process reading /etc/shadow — credential theft on Linux.",
              "HIGH", "T1003.008", "credential_access",
              cmdline_any=["/etc/shadow", "/etc/passwd"],
              process_name_any=["cat", "grep", "python3", "python", "ruby", "perl"], risk_score=80),

    # ── Discovery ──────────────────────────────────────────────────────────────
    SigmaRule("SIG-030", "Network recon — ipconfig/ifconfig",
              "Network enumeration commands — early-stage recon.",
              "LOW", "T1016", "discovery",
              process_name_any=["ipconfig.exe", "ifconfig", "ip"],
              cmdline_any=["/all", "-a", "addr show"], risk_score=25),

    SigmaRule("SIG-031", "Domain/AD enumeration",
              "Active Directory enumeration — attacker mapping domain.",
              "MEDIUM", "T1018", "discovery",
              process_name_any=["net.exe", "nltest.exe", "dsquery.exe", "ldapsearch"],
              cmdline_any=["domain", "group", "localgroup", "user", "/domain",
                           "trusts", "dclist"], risk_score=50),

    SigmaRule("SIG-032", "Process discovery",
              "Bulk process listing — attacker fingerprinting environment.",
              "LOW", "T1057", "discovery",
              process_name_any=["tasklist.exe", "ps"],
              cmdline_any=["/v", "-aux", "-ef"], risk_score=20),

    # ── Lateral Movement ───────────────────────────────────────────────────────
    SigmaRule("SIG-040", "PsExec lateral movement",
              "PsExec used to execute on remote host.",
              "HIGH", "T1021.002", "lateral_movement",
              process_name_any=["psexec.exe", "psexesvc.exe"],
              cmdline_any=["\\\\", "-accepteula"], risk_score=80),

    SigmaRule("SIG-041", "WMI remote execution",
              "WMIC connecting to remote system — lateral movement.",
              "HIGH", "T1047", "lateral_movement",
              process_name_any=["wmic.exe"],
              cmdline_any=["/node:", "process call create"], risk_score=75),

    SigmaRule("SIG-042", "RDP tunneling",
              "SSH/netcat tunneling RDP — lateral movement.",
              "HIGH", "T1021.001", "lateral_movement",
              process_name_any=["ssh", "nc", "ncat", "socat"],
              cmdline_any=["3389", "-L 3389", "-R 3389"], risk_score=80),

    # ── Defense Evasion ────────────────────────────────────────────────────────
    SigmaRule("SIG-050", "Windows event log clearing",
              "Event log cleared — attacker covering tracks.",
              "HIGH", "T1070.001", "defense_evasion",
              process_name_any=["wevtutil.exe"],
              cmdline_any=["cl ", "clear-log"], risk_score=85),

    SigmaRule("SIG-051", "AV/Defender disabling",
              "Attempt to disable Windows Defender.",
              "CRITICAL", "T1562.001", "defense_evasion",
              process_name_any=["powershell.exe", "cmd.exe"],
              cmdline_any=["Set-MpPreference -Disable", "DisableRealtimeMonitoring",
                           "DisableIOAVProtection", "sc stop windefend"], risk_score=95),

    SigmaRule("SIG-052", "Timestomp — file time modification",
              "Process modifying file timestamps — anti-forensics.",
              "MEDIUM", "T1070.006", "defense_evasion",
              cmdline_any=["touch -t", "SetFileTime", "timestomp"], risk_score=55),

    SigmaRule("SIG-053", "Binary obfuscation",
              "Process using obfuscation techniques.",
              "HIGH", "T1027", "defense_evasion",
              cmdline_any=["FromBase64String", "Convert.FromBase64", "base64 -d |",
                           "base64 -D |", "[char]", "char("], risk_score=70),

    # ── C2 / Exfiltration ──────────────────────────────────────────────────────
    SigmaRule("SIG-060", "DNS TXT record query — C2 channel",
              "Querying DNS TXT records — possible C2 over DNS.",
              "MEDIUM", "T1071.004", "command_and_control",
              process_name_any=["nslookup", "dig", "powershell", "python3"],
              cmdline_any=["TXT", "type=txt", "type TXT", "-t TXT"], risk_score=55),

    SigmaRule("SIG-061", "Data compressed before exfil",
              "Large archive created then transferred — data staging.",
              "HIGH", "T1560", "collection",
              process_name_any=["7z.exe", "winrar.exe", "zip", "tar"],
              cmdline_any=["a ", "-r ", "-mx=", "cf ", "-czf"], risk_score=65),

    SigmaRule("SIG-062", "Rclone sync to cloud — exfiltration",
              "Rclone syncing data to remote cloud — data exfiltration.",
              "CRITICAL", "T1567.002", "exfiltration",
              process_name_any=["rclone"],
              cmdline_any=["copy", "sync", "move"], risk_score=90),

    # ── Linux-specific ─────────────────────────────────────────────────────────
    SigmaRule("SIG-070", "LD_PRELOAD injection",
              "LD_PRELOAD set in environment — library injection on Linux.",
              "HIGH", "T1055.001", "defense_evasion",
              cmdline_any=["LD_PRELOAD=", "ld_preload"], risk_score=80),

    SigmaRule("SIG-071", "SSH authorized_keys modification",
              "Process modifying SSH authorized_keys — persistence.",
              "HIGH", "T1098.004", "persistence",
              cmdline_any=["authorized_keys", ".ssh/authorized"], risk_score=80),

    SigmaRule("SIG-072", "Cron persistence via shell",
              "Cron job added via echo/shell redirect — persistence.",
              "HIGH", "T1053.003", "persistence",
              cmdline_any=["crontab -", ">> /etc/cron", "echo * * * * *",
                           "/etc/cron.d/"], risk_score=75),

    # ── Initial Access ───────────────────────────────────────────────────────────
    SigmaRule("SIG-080", "Office application spawning shell/script host",
              "Word/Excel/PowerPoint/Outlook launched a shell or script "
              "interpreter — classic malicious macro / phishing attachment execution.",
              "CRITICAL", "T1204.002", "initial_access",
              process_name_any=["powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe",
                                 "cscript.exe", "mshta.exe"],
              parent_name_any=["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"],
              risk_score=90),

    # ── Privilege Escalation ─────────────────────────────────────────────────────
    SigmaRule("SIG-081", "UAC bypass via trusted auto-elevate binary",
              "Shell spawned by fodhelper/eventvwr/sdclt — these never launch a "
              "shell in normal use; classic registry-hijack UAC bypass.",
              "HIGH", "T1548.002", "privilege_escalation",
              process_name_any=["cmd.exe", "powershell.exe"],
              parent_name_any=["fodhelper.exe", "eventvwr.exe", "sdclt.exe",
                                "computerdefaults.exe"],
              risk_score=85),

    # ── Defense Evasion ──────────────────────────────────────────────────────────
    SigmaRule("SIG-082", "BITSAdmin download abuse",
              "BITSAdmin used to transfer a file — LOLBin technique that evades "
              "process-based download monitoring.",
              "HIGH", "T1197", "defense_evasion",
              process_name_any=["bitsadmin.exe"],
              cmdline_any=["/transfer", "/addfile", "/download"], risk_score=78),

    SigmaRule("SIG-083", "AMSI bypass pattern",
              "PowerShell command line references AMSI internals — attempt to "
              "disable antimalware scanning before running a payload.",
              "CRITICAL", "T1562.001", "defense_evasion",
              process_name_any=["powershell.exe", "pwsh.exe"],
              cmdline_any=["amsiutils", "amsiinitfailed", "amsi.dll",
                           "amsiscanbuffer"], risk_score=88),

    # ── Persistence ────────────────────────────────────────────────────────────
    SigmaRule("SIG-084", "WMI event subscription persistence",
              "WMI permanent event subscription created — fileless persistence "
              "that survives reboots without a scheduled task or registry run key.",
              "HIGH", "T1546.003", "persistence",
              process_name_any=["wmic.exe", "mofcomp.exe", "powershell.exe"],
              cmdline_any=["__eventfilter", "commandlineeventconsumer",
                           "root\\subscription"], risk_score=82),

    # ── Credential Access ────────────────────────────────────────────────────────
    SigmaRule("SIG-085", "Kerberoasting / Kerberos ticket abuse",
              "Rubeus or Mimikatz-style Kerberos ticket request pattern — "
              "used to extract service-account credentials for offline cracking.",
              "HIGH", "T1558.003", "credential_access",
              cmdline_any=["kerberoast", "asktgs", "asktgt", "kerberos::",
                           "/spn:", "s4u/user:"], risk_score=85),

    # ── Lateral Movement ─────────────────────────────────────────────────────────
    SigmaRule("SIG-086", "Impacket-style remote execution tooling",
              "Command line matches Impacket's wmiexec/psexec/smbexec/secretsdump "
              "— common post-exploitation remote-execution toolkit.",
              "HIGH", "T1021.002", "lateral_movement",
              cmdline_any=["wmiexec.py", "psexec.py", "smbexec.py",
                           "secretsdump.py", "wmiexec.", "atexec.py"], risk_score=85),

    # ── Collection ───────────────────────────────────────────────────────────────
    SigmaRule("SIG-087", "Screen/clipboard capture tool invocation",
              "Command-line invocation of a screenshot or clipboard-dumping "
              "utility outside normal user tooling — pre-exfiltration data collection.",
              "MEDIUM", "T1113", "collection",
              cmdline_any=["get-clipboard", "clip.exe /", "screencapture -x",
                           "import -window root"], risk_score=55),
]


class SigmaEngine:
    ENGINE = "Sigma"

    def __init__(self):
        self._alerted = set()
        self._lock    = threading.Lock()
        log.info(f"SigmaEngine loaded {len(SIGMA_RULES)} rules")

    def scan(self, event_bus):
        if not PSUTIL:
            return
        try:
            procs = list(psutil.process_iter(
                ["pid", "name", "ppid", "cmdline", "username"]
            ))
        except Exception:
            return

        proc_map = {p.pid: p for p in procs}

        for proc in procs:
            try:
                info    = proc.info
                pid     = info["pid"]
                name    = (info["name"] or "").lower()
                cmdline = " ".join(info["cmdline"] or []).lower()
                ppid    = info.get("ppid", 0)
                parent  = proc_map.get(ppid)
                pname   = (parent.info["name"] or "").lower() if parent else ""

                for rule in SIGMA_RULES:
                    # Check process name
                    name_ok = (not rule.process_name_any or
                               any(p.lower() in name for p in rule.process_name_any))
                    # Check cmdline any
                    cmd_any_ok = (not rule.cmdline_any or
                                  any(c.lower() in cmdline for c in rule.cmdline_any))
                    # Check cmdline all
                    cmd_all_ok = (not rule.cmdline_all or
                                  all(c.lower() in cmdline for c in rule.cmdline_all))
                    # Check parent
                    parent_ok  = (not rule.parent_name_any or
                                  any(p.lower() in pname for p in rule.parent_name_any))

                    if name_ok and cmd_any_ok and cmd_all_ok and parent_ok:
                        alert_key = f"{rule.rule_id}:{pid}"
                        with self._lock:
                            if alert_key in self._alerted:
                                continue
                            self._alerted.add(alert_key)

                        from core.alert_manager import Alert
                        a = Alert(
                            alert_type   = f"SIGMA_{rule.rule_id}",
                            severity     = rule.severity,
                            title        = f"[{rule.rule_id}] {rule.title}",
                            description  = (
                                f"{rule.description} | "
                                f"Process: {name} (PID {pid}) | "
                                f"Cmdline: {cmdline[:200]}"
                            ),
                            process_info = {
                                "pid": pid, "name": name,
                                "cmdline": cmdline[:300],
                                "rule_id": rule.rule_id,
                                "parent": pname,
                            },
                            risk_score   = rule.risk_score,
                            mitre_tactic = rule.mitre_tactic,
                            mitre_tech   = rule.mitre_tech,
                            engine       = self.ENGINE,
                        )
                        event_bus.publish("alert", {"kind": "alert", "alert": a})

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                log.debug(f"Sigma scan error: {e}")

        with self._lock:
            if len(self._alerted) > 5000:
                self._alerted.clear()
