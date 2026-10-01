#!/usr/bin/env python3
"""
detection/behavioral/dna_engine.py — Behavioral DNA Engine

Builds a statistical baseline (mean + stdev) of CPU, memory, threads,
and network connections per (process_name, username) pair.

Flags Z-score > 5σ deviations as anomalies — the same process
behaving radically differently than its historical norm.

Source: NeuralGuard BehavioralDNA, enhanced with MITRE mapping.
"""

import logging, platform, statistics, threading, time
from collections import defaultdict, deque
from core.alert_manager import Alert

try:
    import psutil
    PSUTIL = True
except ImportError:
    PSUTIL = False

log    = logging.getLogger("SentinelEDR.BehavioralDNA")
SYSTEM = platform.system()

RISK_WEIGHTS = {
    "cpu":         25,
    "memory":      20,
    "threads":     15,
    "connections": 20,
}

Z_THRESHOLD     = 5.0   # standard deviations
MIN_SAMPLES     = 20    # minimum observations before scoring (raised from 10)
PROFILE_WINDOW  = 300   # seconds of history per process

# Processes with naturally high variance — raise threshold to reduce noise
HIGH_VARIANCE_PROCESSES = {
    "svchost.exe", "msedgewebview2.exe", "chrome.exe", "msedge.exe",
    "firefox.exe", "brave.exe", "explorer.exe", "dwm.exe",
    "SearchHost.exe", "SearchIndexer.exe", "MsMpEng.exe",
    "RuntimeBroker.exe", "ctfmon.exe", "sihost.exe",
    "taskhostw.exe", "backgroundtaskhost.exe", "wuauclt.exe",
    "audiodg.exe", "fontdrvhost.exe", "WmiPrvSE.exe",
    "dllhost.exe", "TextInputHost.exe", "conhost.exe",
    "SearchProtocolHost.exe", "ApplicationFrameHost.exe",
}

Z_THRESHOLD_HIGH_VARIANCE = 8.0  # stricter threshold for noisy processes

# Minimum stdev per metric. A flat "stdev or 0.01" floor let a metric that
# happened to be near-constant over its first MIN_SAMPLES readings (e.g. a
# browser sitting at 4 connections right after launch) turn the very next
# ordinary fluctuation into a 20-30+ sigma "anomaly" — exactly the kind of
# false positive that fired repeatedly in the first few minutes of a real
# run. These floors reflect realistic baseline jitter for each metric.
MIN_STDEV = {
    "cpu":         2.0,   # percent
    "memory":      15.0,  # MB
    "threads":     1.5,
    "connections": 2.0,
}


class ProcessProfile:
    """Rolling statistical profile for a single (process, user) pair."""
    def __init__(self, key: str):
        self.key      = key
        self._cpu     = deque(maxlen=200)
        self._mem     = deque(maxlen=200)
        self._threads = deque(maxlen=200)
        self._conns   = deque(maxlen=200)

    def record(self, cpu: float, mem_mb: float, threads: int, conns: int):
        self._cpu.append(cpu)
        self._mem.append(mem_mb)
        self._threads.append(float(threads))
        self._conns.append(float(conns))

    def ready(self) -> bool:
        return len(self._cpu) >= MIN_SAMPLES

    def z_scores(self, cpu, mem_mb, threads, conns) -> dict:
        def _z(series, val, floor):
            if len(series) < 2:
                return 0.0
            try:
                mean = statistics.mean(series)
                sd   = max(statistics.stdev(series), floor)
                return abs((val - mean) / sd)
            except Exception:
                return 0.0

        return {
            "cpu":         _z(self._cpu,     cpu,            MIN_STDEV["cpu"]),
            "memory":      _z(self._mem,     mem_mb,         MIN_STDEV["memory"]),
            "threads":     _z(self._threads, float(threads), MIN_STDEV["threads"]),
            "connections": _z(self._conns,   float(conns),   MIN_STDEV["connections"]),
        }


class BehavioralDNAEngine:
    """
    Scan cycle: iterate all running processes, record metrics,
    compute Z-scores against historical profile, alert on outliers.
    """

    ENGINE = "BehavioralDNA"

    def __init__(self):
        self._profiles: dict[str, ProcessProfile] = {}
        self._lock = threading.Lock()

    def _key(self, proc) -> str:
        try:
            return f"{proc.name()}:{proc.username()}"
        except Exception:
            return "unknown:unknown"

    def scan(self, event_bus):
        if not PSUTIL:
            return
        try:
            procs = list(psutil.process_iter(
                ["pid", "name", "username", "cpu_percent",
                 "memory_info", "num_threads", "net_connections"]
            ))
        except Exception:
            return

        for proc in procs:
            try:
                info  = proc.info
                key   = f"{info['name']}:{info['username']}"
                cpu   = info["cpu_percent"] or 0.0
                mem   = (info["memory_info"].rss / 1048576) if info["memory_info"] else 0.0
                thrs  = info["num_threads"] or 0
                conns = 0
                try:
                    conns = len(proc.net_connections())
                except (psutil.AccessDenied, AttributeError):
                    pass

                with self._lock:
                    if key not in self._profiles:
                        self._profiles[key] = ProcessProfile(key)
                    profile = self._profiles[key]

                if profile.ready():
                    zs = profile.z_scores(cpu, mem, thrs, conns)
                    # Use stricter threshold for naturally noisy processes
                    thresh = Z_THRESHOLD_HIGH_VARIANCE if (info["name"] or "") in HIGH_VARIANCE_PROCESSES else Z_THRESHOLD
                    triggered = {k: v for k, v in zs.items() if v > thresh}
                    if triggered:
                        risk = min(100, sum(
                            RISK_WEIGHTS.get(k, 10) * min(z / Z_THRESHOLD, 3)
                            for k, z in triggered.items()
                        ))
                        severity = (
                            "CRITICAL" if risk >= 80 else
                            "HIGH"     if risk >= 60 else
                            "MEDIUM"   if risk >= 40 else "LOW"
                        )
                        fields = ", ".join(
                            f"{k}(z={z:.1f})" for k, z in triggered.items()
                        )
                        from core.alert_manager import AlertManager
                        a = Alert(
                            alert_type   = "BEHAVIORAL_ANOMALY",
                            severity     = severity,
                            title        = f"Behavioral anomaly: {info['name']}",
                            description  = (
                                f"Process '{info['name']}' (PID {info['pid']}) "
                                f"deviates {fields} from its historical baseline."
                            ),
                            process_info = {
                                "pid": info["pid"], "name": info["name"],
                                "user": info["username"], "cpu": cpu,
                                "mem_mb": round(mem, 1), "threads": thrs,
                            },
                            risk_score   = int(risk),
                            mitre_tactic = "defense_evasion",
                            mitre_tech   = "T1036",
                            engine       = self.ENGINE,
                        )
                        event_bus.publish("alert", {"kind": "alert", "alert": a})

                profile.record(cpu, mem, thrs, conns)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                log.debug(f"DNA scan error: {e}")
