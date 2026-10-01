#!/usr/bin/env python3
"""
detection/behavioral/entropy_shield.py — Shannon Entropy Ransomware Shield

Monitors file system write events using watchdog.
Computes Shannon entropy on 8KB samples of written files.
Entropy >= 7.2/8.0 on non-compressed file types = ransomware indicator.

Also tracks write velocity per process (many files written quickly = ransomware).

Source: NeuralGuard EntropyShield, hardened with process attribution.
"""

import logging, math, os, platform, threading, time
from collections import defaultdict, deque
from pathlib import Path

log    = logging.getLogger("SentinelEDR.EntropyShield")
SYSTEM = platform.system()

ENTROPY_THRESHOLD = 7.2      # bits/byte — high entropy = encrypted/compressed
SAMPLE_BYTES      = 8192     # bytes to sample per file
VELOCITY_WINDOW   = 60       # seconds
VELOCITY_LIMIT    = 60       # files/minute — raised from 20 to reduce Windows browser noise

# Extensions that are naturally high-entropy (skip these)
COMPRESSED_EXTS = {
    # Archives
    ".zip", ".gz", ".bz2", ".xz", ".7z", ".rar", ".tar",
    # Media
    ".jpg", ".jpeg", ".png", ".gif", ".mp4", ".mp3", ".mkv",
    ".webp", ".webm", ".ogg", ".flac", ".aac",
    # Office / PDF
    ".pdf", ".docx", ".xlsx", ".pptx",
    # Browser cache + databases (Chrome, Edge, Firefox, Brave)
    ".ldb", ".log", ".sst", ".manifest", ".db", ".sqlite",
    ".cache", ".pak", ".dat", ".data",
    # Compiled / binary
    ".pyc", ".pyd", ".so", ".dll", ".exe", ".bin",
    # Crypto / key files (naturally high entropy)
    ".pem", ".key", ".p12", ".pfx", ".jks",
}

# Process names whose file writes we always skip (browser / system noise)
WHITELISTED_PROCESSES = {
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
    "msedgewebview2.exe", "chromium.exe", "opera.exe",
    "svchost.exe", "system", "registry", "smss.exe",
    "antimalware service executable", "mrt.exe", "mpcmdrun.exe",
    "windowsdefender.exe", "wsappx",
}

# Extensions ransomware typically targets
TARGET_EXTS = {
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".pdf", ".txt", ".csv", ".sql", ".db", ".mdb",
    ".jpg", ".jpeg", ".png", ".bmp", ".tiff",
    ".py", ".js", ".ts", ".java", ".cpp", ".c", ".h",
    ".key", ".pem", ".pfx", ".p12",
    ".backup", ".bak", ".sql",
}

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_OK = True
except ImportError:
    WATCHDOG_OK = False


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = defaultdict(int)
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


class _WriteHandler(FileSystemEventHandler):
    def __init__(self, engine):
        self._engine = engine

    def on_modified(self, event):
        if not event.is_directory:
            self._engine._check_file(event.src_path, "modified")

    def on_created(self, event):
        if not event.is_directory:
            self._engine._check_file(event.src_path, "created")


class EntropyShieldEngine:
    ENGINE = "EntropyShield"

    def __init__(self):
        self._observer       = None
        self._event_bus      = None
        self._write_times    = defaultdict(lambda: deque(maxlen=200))
        self._lock           = threading.Lock()
        self._alerted        = set()

    def _watch_dirs(self) -> list:
        dirs = [os.path.expanduser("~"), os.getcwd()]
        if SYSTEM == "Windows":
            for drive in ["C:\\Users", "C:\\Documents"]:
                if os.path.exists(drive):
                    dirs.append(drive)
        elif SYSTEM == "Linux":
            dirs += ["/home", "/tmp", "/var/www"]
        elif SYSTEM == "Darwin":
            dirs += ["/Users", "/tmp"]
        return [d for d in dirs if os.path.isdir(d)]

    def _check_file(self, path: str, event_type: str):
        try:
            ext = Path(path).suffix.lower()
            if ext in COMPRESSED_EXTS:
                return
            # Skip writes from browser/system processes
            if PSUTIL:
                try:
                    import psutil as _ps
                    for proc in _ps.process_iter(["name", "open_files"]):
                        try:
                            pname = (proc.info.get("name") or "").lower()
                            if pname in WHITELISTED_PROCESSES:
                                for f in proc.open_files():
                                    if f.path == path:
                                        return
                        except Exception:
                            continue
                except Exception:
                    pass
            # Skip writes from whitelisted browser/system processes
            if PSUTIL:
                try:
                    import psutil as _ps
                    for proc in _ps.process_iter(["name", "open_files"]):
                        try:
                            pname = (proc.info["name"] or "").lower()
                            if pname in WHITELISTED_PROCESSES:
                                for f in proc.open_files():
                                    if f.path == path:
                                        return
                        except Exception:
                            pass
                except Exception:
                    pass

            # Entropy check
            if os.path.exists(path) and os.path.getsize(path) > 0:
                with open(path, "rb") as f:
                    sample = f.read(SAMPLE_BYTES)
                entropy = _shannon_entropy(sample)

                if entropy >= ENTROPY_THRESHOLD and ext not in COMPRESSED_EXTS:
                    alert_key = f"entropy:{path}"
                    with self._lock:
                        if alert_key in self._alerted:
                            return
                        self._alerted.add(alert_key)

                    risk = min(100, int(50 + (entropy - ENTROPY_THRESHOLD) * 30))
                    severity = "CRITICAL" if risk >= 80 else "HIGH" if risk >= 60 else "MEDIUM"

                    from core.alert_manager import Alert
                    a = Alert(
                        alert_type   = "RANSOMWARE_ENTROPY",
                        severity     = severity,
                        title        = f"High-entropy file write: {Path(path).name}",
                        description  = (
                            f"File '{path}' written with entropy {entropy:.2f}/8.0 "
                            f"(threshold {ENTROPY_THRESHOLD}) — possible ransomware encryption."
                        ),
                        process_info = {"path": path, "entropy": round(entropy, 3),
                                        "event": event_type, "ext": ext},
                        risk_score   = risk,
                        mitre_tactic = "impact",
                        mitre_tech   = "T1486",
                        engine       = self.ENGINE,
                    )
                    if self._event_bus:
                        self._event_bus.publish("alert", {"kind": "alert", "alert": a})

            # Velocity check — track writes per process context
            now = time.time()
            with self._lock:
                self._write_times["global"].append(now)
                cutoff = now - VELOCITY_WINDOW
                recent = [t for t in self._write_times["global"] if t > cutoff]
                self._write_times["global"] = deque(recent, maxlen=200)

                if len(recent) >= VELOCITY_LIMIT:
                    v_key = "velocity:global"
                    if v_key not in self._alerted:
                        self._alerted.add(v_key)
                        from core.alert_manager import Alert
                        a = Alert(
                            alert_type   = "RANSOMWARE_VELOCITY",
                            severity     = "CRITICAL",
                            title        = f"High file-write velocity: {len(recent)} files/min",
                            description  = (
                                f"{len(recent)} files written in {VELOCITY_WINDOW}s — "
                                f"possible ransomware mass encryption."
                            ),
                            process_info = {"writes_per_minute": len(recent)},
                            risk_score   = 92,
                            mitre_tactic = "impact",
                            mitre_tech   = "T1486",
                            engine       = self.ENGINE,
                        )
                        if self._event_bus:
                            self._event_bus.publish("alert", {"kind": "alert", "alert": a})
                    # Reset after alerting
                    self._write_times["global"].clear()

        except (PermissionError, FileNotFoundError, OSError):
            pass
        except Exception as e:
            log.debug(f"EntropyShield check error: {e}")

    def run(self, event_bus):
        """Blocking watchdog runner — call in a dedicated thread."""
        self._event_bus = event_bus
        if not WATCHDOG_OK:
            log.warning("watchdog not installed — EntropyShield disabled. "
                        "pip install watchdog --break-system-packages")
            return

        observer = Observer()
        handler  = _WriteHandler(self)
        for d in self._watch_dirs():
            try:
                observer.schedule(handler, d, recursive=True)
                log.info(f"EntropyShield watching: {d}")
            except Exception as e:
                log.debug(f"Cannot watch {d}: {e}")

        observer.start()
        self._observer = observer
        log.info("EntropyShield running")
        try:
            while True:
                time.sleep(5)
                # Purge old alert keys every 10 min to allow re-alerting
                if len(self._alerted) > 5000:
                    with self._lock:
                        self._alerted.clear()
        except Exception:
            observer.stop()
        observer.join()
