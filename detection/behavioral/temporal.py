#!/usr/bin/env python3
"""
detection/behavioral/temporal.py — Temporal Anomaly Engine

Tracks what hour each process historically runs.
Alerts if a process runs in an hour with <2% historical frequency.
Example: svchost.exe running at 3 AM when it always runs 9-5 = suspicious.

Source: NeuralGuard TemporalAnomalyEngine.
"""

import logging, threading, time
from collections import defaultdict, deque
from datetime import datetime

log = logging.getLogger("SentinelEDR.TemporalAnomaly")

try:
    import psutil
    PSUTIL = True
except ImportError:
    PSUTIL = False

MIN_OBSERVATIONS = 30     # minimum before temporal scoring
RARE_THRESHOLD   = 0.02   # < 2% frequency in this hour = anomaly


class TemporalAnomalyEngine:
    ENGINE = "TemporalAnomaly"

    def __init__(self):
        # {proc_name: {hour: count}}
        self._hour_counts = defaultdict(lambda: defaultdict(int))
        self._total_obs   = defaultdict(int)
        self._alerted     = set()
        self._lock        = threading.Lock()

    def scan(self, event_bus):
        if not PSUTIL:
            return
        hour = datetime.now().hour

        try:
            procs = list(psutil.process_iter(["pid", "name", "username"]))
        except Exception:
            return

        for proc in procs:
            try:
                info = proc.info
                name = info["name"] or "unknown"

                with self._lock:
                    self._hour_counts[name][hour] += 1
                    self._total_obs[name] += 1
                    total = self._total_obs[name]
                    hour_count = self._hour_counts[name][hour]

                if total < MIN_OBSERVATIONS:
                    continue

                freq = hour_count / total
                if freq < RARE_THRESHOLD:
                    alert_key = f"{name}:{hour}"
                    with self._lock:
                        if alert_key in self._alerted:
                            continue
                        self._alerted.add(alert_key)

                    from core.alert_manager import Alert
                    a = Alert(
                        alert_type   = "TEMPORAL_ANOMALY",
                        severity     = "MEDIUM",
                        title        = f"Temporal anomaly: {name} at {hour:02d}:00",
                        description  = (
                            f"Process '{name}' running at hour {hour:02d}:00 with only "
                            f"{freq*100:.1f}% historical frequency ({hour_count}/{total} obs). "
                            f"Possible scheduled task, persistence, or after-hours attack."
                        ),
                        process_info = {
                            "pid": info["pid"], "name": name,
                            "hour": hour, "freq_pct": round(freq * 100, 2),
                            "observations": total,
                        },
                        risk_score   = 45,
                        mitre_tactic = "defense_evasion",
                        mitre_tech   = "T1036",
                        engine       = self.ENGINE,
                    )
                    event_bus.publish("alert", {"kind": "alert", "alert": a})

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                log.debug(f"Temporal scan error: {e}")
