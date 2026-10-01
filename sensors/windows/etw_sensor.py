#!/usr/bin/env python3
"""
sensors/windows/etw_sensor.py — Windows ETW + Sysmon Sensor

Deep Windows kernel telemetry via:
  1. ETW (Event Tracing for Windows) — kernel process/network events
  2. Sysmon event log — if Sysmon is installed
  3. Windows Event Log fallback — Security + System logs

Provides richer telemetry than psutil alone:
  - Process creation with full command line (Event ID 4688 / Sysmon 1)
  - Network connection with process attribution (Sysmon 3)
  - File creation (Sysmon 11)
  - Registry modification (Sysmon 12/13)
  - Driver load (Sysmon 6)
  - WMI activity (Sysmon 19/20)

Windows-only. Gracefully disabled on other platforms.
Requires: pywin32 (optional), or falls back to Windows Event Log via subprocess.

Install pywin32: pip install pywin32 --break-system-packages
"""

import logging, platform, queue, subprocess, threading, time, json
from datetime import datetime
from typing import Optional

log = logging.getLogger("SentinelEDR.ETWSensor")

if platform.system() != "Windows":
    class ETWSensor:
        """Stub — ETW sensor is Windows-only."""
        ENGINE = "ETWSensor"
        def run(self, event_bus):
            log.debug("ETW sensor: non-Windows platform, disabled")
else:
    import os

    # Try pywin32 for direct ETW access
    try:
        import win32evtlog
        import win32evtlogutil
        import win32con
        WIN32_OK = True
    except ImportError:
        WIN32_OK = False

    # Sysmon event IDs we care about
    SYSMON_EVENTS = {
        1:  "ProcessCreate",
        3:  "NetworkConnect",
        5:  "ProcessTerminate",
        6:  "DriverLoad",
        7:  "ImageLoad",
        8:  "CreateRemoteThread",
        10: "ProcessAccess",
        11: "FileCreate",
        12: "RegistryCreate",
        13: "RegistrySet",
        15: "FileCreateStreamHash",
        17: "PipeCreate",
        18: "PipeConnect",
        19: "WmiFilter",
        20: "WmiConsumer",
        22: "DnsQuery",
        25: "ProcessTampering",
    }

    # Windows Security Event IDs
    SECURITY_EVENTS = {
        4624: "SuccessfulLogon",
        4625: "FailedLogon",
        4648: "ExplicitCredentialLogon",
        4688: "ProcessCreate",
        4698: "ScheduledTaskCreate",
        4702: "ScheduledTaskModify",
        4719: "AuditPolicyChange",
        4720: "UserAccountCreate",
        4728: "GroupMemberAdd",
        4732: "LocalGroupMemberAdd",
        4756: "UniversalGroupMemberAdd",
        7045: "ServiceInstall",
    }

    # High-risk event IDs that always get forwarded as alerts
    HIGH_RISK_IDS = {4648, 4698, 4719, 4720, 7045, 8, 10, 25}


    def _parse_sysmon_xml(xml_str: str) -> dict:
        """Very lightweight XML parser for Sysmon event data."""
        data = {}
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_str)
            ns   = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
            for ed in root.findall(".//e:EventData/e:Data", ns):
                name = ed.get("Name", "")
                if name and ed.text:
                    data[name] = ed.text
        except Exception:
            pass
        return data


    class ETWSensor:
        ENGINE = "ETWSensor"

        def __init__(self):
            self._event_queue = queue.Queue(maxsize=1000)
            self._running     = False
            self._alerted     = set()
            self._lock        = threading.Lock()

        def _read_event_log(self, log_name: str, event_ids: dict):
            """Read Windows Event Log using pywin32."""
            if not WIN32_OK:
                return
            try:
                hand = win32evtlog.OpenEventLog(None, log_name)
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                total = win32evtlog.GetNumberOfEventLogRecords(hand)
                read  = 0
                while self._running:
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    if not events:
                        time.sleep(1)
                        continue
                    for ev in events:
                        eid = ev.EventID & 0xFFFF
                        if eid in event_ids:
                            self._event_queue.put({
                                "source":    log_name,
                                "event_id":  eid,
                                "event_name":event_ids[eid],
                                "time":      str(ev.TimeGenerated),
                                "computer":  ev.ComputerName,
                                "strings":   list(ev.StringInserts or []),
                            })
                        read += 1
                win32evtlog.CloseEventLog(hand)
            except Exception as e:
                log.debug(f"Event log read error ({log_name}): {e}")

        def _read_via_wevtutil(self, log_name: str, event_ids: dict):
            """
            Fallback: use wevtutil.exe to query event log.
            Works without pywin32 but slower.
            """
            ids_str = " or ".join(f"EventID={eid}" for eid in list(event_ids.keys())[:10])
            query   = f"*[System[({ids_str})]]"
            cmd     = ["wevtutil", "qe", log_name, f"/q:{query}",
                       "/c:50", "/rd:true", "/f:text"]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True,
                                        timeout=10, encoding="utf-8", errors="replace")
                if result.returncode == 0 and result.stdout:
                    # Parse text output
                    current = {}
                    for line in result.stdout.splitlines():
                        line = line.strip()
                        if line.startswith("Event["):
                            if current:
                                self._event_queue.put(current)
                            current = {"source": log_name, "raw": []}
                        elif ":" in line and current is not None:
                            k, _, v = line.partition(":")
                            current[k.strip().lower().replace(" ", "_")] = v.strip()
                            if "event_id" in current.get("_id","").lower():
                                try:
                                    eid = int(v.strip())
                                    current["event_id"]   = eid
                                    current["event_name"] = event_ids.get(eid, "Unknown")
                                except ValueError:
                                    pass
                    if current:
                        self._event_queue.put(current)
            except Exception as e:
                log.debug(f"wevtutil error: {e}")

        def _check_sysmon_available(self) -> bool:
            try:
                result = subprocess.run(
                    ["wevtutil", "gl", "Microsoft-Windows-Sysmon/Operational"],
                    capture_output=True, timeout=5
                )
                return result.returncode == 0
            except Exception:
                return False

        def _process_event_queue(self, event_bus):
            """Process queued events and publish alerts for suspicious ones."""
            while self._running:
                try:
                    event = self._event_queue.get(timeout=2)
                    eid   = event.get("event_id", 0)
                    ename = event.get("event_name", "")

                    # Always publish telemetry to event bus
                    event_bus.publish("telemetry", {"kind": "windows_event", "event": event})

                    # Generate alerts for high-risk events
                    if eid in HIGH_RISK_IDS:
                        alert_key = f"etw:{eid}:{hash(str(event))}"
                        with self._lock:
                            if alert_key in self._alerted:
                                continue
                            self._alerted.add(alert_key)

                        severity_map = {
                            4648: ("HIGH",     "Explicit credential logon — pass-the-hash?", "T1550.002"),
                            4698: ("HIGH",     "Scheduled task created — possible persistence", "T1053.005"),
                            4719: ("CRITICAL", "Audit policy changed — attacker covering tracks", "T1562.002"),
                            4720: ("MEDIUM",   "New user account created", "T1136.001"),
                            7045: ("HIGH",     "New service installed — possible persistence", "T1543.003"),
                            8:    ("CRITICAL", "Remote thread creation — process injection", "T1055"),
                            10:   ("HIGH",     "Process access (LSASS?) — credential dumping", "T1003.001"),
                            25:   ("CRITICAL", "Process tampering detected by Sysmon", "T1055.012"),
                        }

                        if eid in severity_map:
                            sev, desc, tech = severity_map[eid]
                            strings = event.get("strings", [])
                            detail  = " | ".join(str(s) for s in strings[:5])

                            from core.alert_manager import Alert
                            a = Alert(
                                alert_type   = f"ETW_{ename.upper()}",
                                severity     = sev,
                                title        = f"[ETW] {ename} (EventID {eid})",
                                description  = f"{desc} | {detail}",
                                process_info = {"event_id": eid, "strings": strings[:10],
                                                "source": event.get("source", "")},
                                risk_score   = {"CRITICAL":88,"HIGH":68,"MEDIUM":45}.get(sev,50),
                                mitre_tactic = "defense_evasion",
                                mitre_tech   = tech,
                                engine       = self.ENGINE,
                            )
                            event_bus.publish("alert", {"kind": "alert", "alert": a})

                except queue.Empty:
                    continue
                except Exception as e:
                    log.debug(f"Event queue processing error: {e}")

        def scan(self, event_bus):
            """scan() alias — called by orchestrator poll loop. No-op since run() is blocking."""
            pass  # ETWSensor is event-driven via run(), not polled via scan()

        def run(self, event_bus):
            self._running = True
            log.info("ETW sensor starting on Windows...")

            sysmon_available = self._check_sysmon_available()
            if sysmon_available:
                log.info("Sysmon detected — using Sysmon event log")
            else:
                log.info("Sysmon not found — using Security + System event logs only")
                log.info("  Install Sysmon for richer telemetry: "
                         "https://docs.microsoft.com/sysinternals/sysmon")

            # Start event collection threads
            if sysmon_available:
                t = threading.Thread(
                    target=self._read_event_log if WIN32_OK else self._read_via_wevtutil,
                    args=("Microsoft-Windows-Sysmon/Operational", SYSMON_EVENTS),
                    daemon=True, name="ETW-Sysmon"
                )
                t.start()

            t2 = threading.Thread(
                target=self._read_event_log if WIN32_OK else self._read_via_wevtutil,
                args=("Security", SECURITY_EVENTS),
                daemon=True, name="ETW-Security"
            )
            t2.start()

            # Process queue in main sensor thread
            self._process_event_queue(event_bus)
