#!/usr/bin/env python3
"""
core/alert_manager.py — Unified Alert Manager

Central alert store for SentinelEDR. Receives alerts from all engines,
persists them, deduplicates, and provides summary reporting.
"""

import hashlib, json, logging, os, threading, time
from collections import defaultdict, deque
from datetime import datetime
from typing import Optional

log = logging.getLogger("SentinelEDR.AlertManager")

SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
SEV_ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}


class Alert:
    def __init__(
        self,
        alert_type:   str,
        severity:     str,
        title:        str,
        description:  str,
        process_info: dict = None,
        risk_score:   int  = 50,
        mitre_tactic: str  = None,
        mitre_tech:   str  = None,
        engine:       str  = "core",
        host:         str  = None,
    ):
        import platform
        self.id           = hashlib.md5(f"{time.time()}{title}".encode()).hexdigest()[:12]
        self.timestamp    = datetime.now().isoformat()
        self.alert_type   = alert_type
        self.severity     = severity.upper()
        self.title        = title
        self.description  = description
        self.process_info = process_info or {}
        self.risk_score   = min(100, max(0, risk_score))
        self.mitre_tactic = mitre_tactic
        self.mitre_tech   = mitre_tech
        self.engine       = engine
        self.host         = host or platform.node()

    def to_dict(self) -> dict:
        return {
            "id":           self.id,
            "timestamp":    self.timestamp,
            "type":         self.alert_type,
            "severity":     self.severity,
            "title":        self.title,
            "description":  self.description,
            "process":      self.process_info,
            "risk_score":   self.risk_score,
            "mitre_tactic": self.mitre_tactic,
            "mitre_tech":   self.mitre_tech,
            "engine":       self.engine,
            "host":         self.host,
        }

    def __str__(self):
        mitre = f" [{self.mitre_tech}]" if self.mitre_tech else ""
        return (f"{SEV_ICONS.get(self.severity,'⚪')} [{self.severity}]"
                f"[{self.engine}]{mitre} {self.title} (risk={self.risk_score})")


class AlertManager:
    MAX_MEM  = 5000   # max alerts kept in memory
    MAX_DISK = 10000  # max alerts persisted

    def __init__(self, alert_file: str):
        self._file   = alert_file
        self._alerts = deque(maxlen=self.MAX_MEM)
        self._lock   = threading.Lock()
        self._counts = defaultdict(int)
        self._dedup  = deque(maxlen=500)   # recent (type, title) pairs for dedup
        self._load_from_file()             # restore persisted alerts on startup

    def _load_from_file(self):
        """Load existing alerts from JSON file into memory on startup."""
        import os, json as _json
        if not os.path.exists(self._file):
            return
        try:
            with open(self._file) as f:
                data = _json.load(f)
            for d in data[-self.MAX_MEM:]:
                sev = d.get("severity", "INFO").upper()
                self._counts[sev] += 1
                # Minimal Alert reconstruction for counting
                a = Alert(
                    alert_type   = d.get("type", "UNKNOWN"),
                    severity     = sev,
                    title        = d.get("title", ""),
                    description  = d.get("description", ""),
                    risk_score   = d.get("risk_score", 0),
                    mitre_tech   = d.get("mitre_tech"),
                    mitre_tactic = d.get("mitre_tactic"),
                    engine       = d.get("engine", "core"),
                )
                self._alerts.append(a)
        except Exception as e:
            log.debug(f"Alert file load error: {e}")

    # ── Public API ────────────────────────────────────────────────────────────

    def add(self, alert: Alert):
        dedup_key = (alert.alert_type, alert.title[:60])
        with self._lock:
            if dedup_key in self._dedup:
                return   # suppress duplicate within recent window
            self._dedup.append(dedup_key)
            self._alerts.append(alert)
            self._counts[alert.severity] += 1
        log.warning(str(alert))
        self._persist(alert)

    def handle(self, event: dict):
        """EventBus callback — receives raw alert dicts from engines."""
        if event.get("kind") != "alert":
            return
        a = event.get("alert")
        if isinstance(a, Alert):
            self.add(a)
        elif isinstance(a, dict):
            self.add(Alert(**a))

    def make_alert(
        self, alert_type, severity, title, description,
        risk_score=50, process_info=None,
        mitre_tactic=None, mitre_tech=None, engine="core"
    ) -> Alert:
        return Alert(
            alert_type=alert_type, severity=severity, title=title,
            description=description, process_info=process_info or {},
            risk_score=risk_score, mitre_tactic=mitre_tactic,
            mitre_tech=mitre_tech, engine=engine,
        )

    def emit(self, event_bus, alert_type, severity, title, description,
             risk_score=50, process_info=None,
             mitre_tactic=None, mitre_tech=None, engine="core"):
        """Convenience: create + emit alert onto the event bus."""
        a = self.make_alert(
            alert_type, severity, title, description,
            risk_score, process_info, mitre_tactic, mitre_tech, engine
        )
        self.add(a)
        event_bus.publish("alert", {"kind": "alert", "alert": a})
        return a

    def get_recent(self, n: int = 50) -> list:
        with self._lock:
            return list(self._alerts)[-n:]

    def get_stats(self) -> dict:
        with self._lock:
            return dict(self._counts)

    def total(self) -> int:
        with self._lock:
            return len(self._alerts)

    def print_summary(self, brief: bool = False):
        stats = self.get_stats()
        total = sum(stats.values())
        if brief:
            log.info(f"Alerts — total:{total} | "
                     f"CRITICAL:{stats.get('CRITICAL',0)} "
                     f"HIGH:{stats.get('HIGH',0)} "
                     f"MEDIUM:{stats.get('MEDIUM',0)} "
                     f"LOW:{stats.get('LOW',0)}")
            return
        print(f"\n{'═'*60}")
        print(f"  SentinelEDR Alert Summary — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'═'*60}")
        print(f"  Total alerts: {total}")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            c = stats.get(sev, 0)
            bar = "█" * min(c, 30)
            print(f"  {SEV_ICONS[sev]} {sev:<10} {c:>5}  {bar}")
        recent = self.get_recent(5)
        if recent:
            print(f"\n  Recent (last 5):")
            for a in reversed(recent):
                print(f"    {a.timestamp[11:19]} {str(a)}")
        print(f"{'═'*60}\n")

    # ── Persistence ───────────────────────────────────────────────────────────

    def _persist(self, alert: Alert):
        try:
            existing = []
            if os.path.exists(self._file):
                try:
                    with open(self._file) as f:
                        existing = json.load(f)
                except (json.JSONDecodeError, OSError):
                    existing = []
            existing.append(alert.to_dict())
            existing = existing[-self.MAX_DISK:]
            with open(self._file, "w") as f:
                json.dump(existing, f, indent=2)
        except Exception as e:
            log.error(f"Persist error: {e}")
