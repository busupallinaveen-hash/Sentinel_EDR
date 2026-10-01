#!/usr/bin/env python3
"""
forensics/forensic_engine.py — Deep Forensics Collection Engine

Triggered by CRITICAL alerts. Collects:
  1. Full process tree snapshot
  2. Network connection state
  3. Open file handles
  4. Process memory maps
  5. Environment variables
  6. Loaded modules / DLLs
  7. User sessions
  8. Scheduled tasks (Windows) / Cron jobs (Linux)
  9. Startup entries (registry/rc files)
  10. Shell history files
  11. Recent file system changes (within last 60s)

Output: timestamped ZIP archive in forensics/ directory.

Source: IDPS forensics modules, adapted for SentinelEDR.
"""

import json, logging, os, platform, shutil, subprocess, time, zipfile
from datetime import datetime
from pathlib import Path
from typing import Optional

log    = logging.getLogger("SentinelEDR.Forensics")
SYSTEM = platform.system()

try:
    import psutil
    PSUTIL = True
except ImportError:
    PSUTIL = False


class ForensicSnapshot:
    """Full system snapshot at a point in time."""

    def __init__(self, trigger: str, pid: Optional[int] = None):
        self.trigger    = trigger
        self.pid        = pid
        self.timestamp  = datetime.now().isoformat()
        self.host       = platform.node()
        self.os         = f"{SYSTEM} {platform.release()}"
        self.data       = {}

    def collect_all(self):
        """Run all collection methods."""
        collectors = [
            ("process_tree",       self._collect_process_tree),
            ("target_process",     self._collect_target_process),
            ("network_state",      self._collect_network_state),
            ("user_sessions",      self._collect_user_sessions),
            ("loaded_modules",     self._collect_loaded_modules),
            ("startup_entries",    self._collect_startup_entries),
            ("scheduled_tasks",    self._collect_scheduled_tasks),
            ("environment",        self._collect_environment),
            ("shell_history",      self._collect_shell_history),
            ("recent_files",       self._collect_recent_files),
            ("disk_usage",         self._collect_disk_usage),
        ]
        for name, fn in collectors:
            try:
                self.data[name] = fn()
            except Exception as e:
                self.data[name] = {"error": str(e)}
        return self

    # ── Collectors ────────────────────────────────────────────────────────────

    def _collect_process_tree(self) -> list:
        if not PSUTIL:
            return []
        procs = []
        for p in psutil.process_iter([
            "pid", "ppid", "name", "exe", "cmdline",
            "username", "status", "create_time", "cpu_percent", "memory_info"
        ]):
            try:
                d = p.info
                if d["memory_info"]:
                    d["mem_mb"] = round(d["memory_info"].rss / 1048576, 1)
                d.pop("memory_info", None)
                d["cmdline"] = (d.get("cmdline") or [])[:10]
                d["create_time"] = datetime.fromtimestamp(
                    d.get("create_time", 0)
                ).isoformat()
                procs.append(d)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return procs

    def _collect_target_process(self) -> dict:
        if not PSUTIL or not self.pid:
            return {}
        try:
            p = psutil.Process(self.pid)
            result = {
                "pid":          p.pid,
                "name":         p.name(),
                "exe":          p.exe(),
                "cmdline":      p.cmdline(),
                "cwd":          p.cwd(),
                "status":       p.status(),
                "username":     p.username(),
                "create_time":  datetime.fromtimestamp(p.create_time()).isoformat(),
                "cpu_percent":  p.cpu_percent(interval=0.2),
                "mem_mb":       round(p.memory_info().rss / 1048576, 2),
                "threads":      p.num_threads(),
                "open_files":   [f.path for f in p.open_files()[:50]],
                "connections":  [
                    {"laddr": str(c.laddr), "raddr": str(c.raddr), "status": c.status}
                    for c in p.net_connections()
                ],
                "memory_maps":  [
                    {"path": m.path, "rss": m.rss}
                    for m in (p.memory_maps() or [])[:30]
                ],
            }
            try:
                result["environ"] = dict(list(p.environ().items())[:50])
            except Exception:
                result["environ"] = {}
            return result
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            return {"error": str(e)}

    def _collect_network_state(self) -> list:
        if not PSUTIL:
            return []
        connections = []
        try:
            for c in psutil.net_connections(kind="inet"):
                connections.append({
                    "pid":    c.pid,
                    "family": str(c.family),
                    "type":   str(c.type),
                    "laddr":  str(c.laddr),
                    "raddr":  str(c.raddr) if c.raddr else "",
                    "status": c.status,
                })
        except Exception:
            pass
        return connections

    def _collect_user_sessions(self) -> list:
        if not PSUTIL:
            return []
        try:
            return [
                {"name": u.name, "terminal": u.terminal,
                 "host": u.host, "started": datetime.fromtimestamp(u.started).isoformat()}
                for u in psutil.users()
            ]
        except Exception:
            return []

    def _collect_loaded_modules(self) -> list:
        """Get loaded kernel modules / DLLs."""
        modules = []
        if SYSTEM == "Linux":
            try:
                with open("/proc/modules") as f:
                    for line in f.readlines()[:100]:
                        parts = line.split()
                        if parts:
                            modules.append(parts[0])
            except Exception:
                pass
        elif SYSTEM == "Windows":
            try:
                result = subprocess.run(
                    ["wmic", "product", "get", "name"],
                    capture_output=True, text=True, timeout=10
                )
                modules = [l.strip() for l in result.stdout.splitlines() if l.strip()][:50]
            except Exception:
                pass
        return modules

    def _collect_startup_entries(self) -> dict:
        entries = {}
        if SYSTEM == "Linux":
            for f in ["/etc/rc.local", "/etc/init.d/"]:
                try:
                    if os.path.isfile(f):
                        with open(f) as fp:
                            entries[f] = fp.read()[:2000]
                    elif os.path.isdir(f):
                        entries[f] = os.listdir(f)[:30]
                except Exception:
                    pass
            # Systemd enabled units
            try:
                r = subprocess.run(
                    ["systemctl", "list-units", "--type=service", "--state=enabled", "--no-pager"],
                    capture_output=True, text=True, timeout=5
                )
                entries["systemd_enabled"] = r.stdout[:3000]
            except Exception:
                pass
        elif SYSTEM == "Windows":
            reg_keys = [
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            ]
            for key in reg_keys:
                try:
                    r = subprocess.run(
                        ["reg", "query", key],
                        capture_output=True, text=True, timeout=5
                    )
                    entries[key] = r.stdout[:2000]
                except Exception:
                    pass
        return entries

    def _collect_scheduled_tasks(self) -> list:
        tasks = []
        if SYSTEM == "Windows":
            try:
                r = subprocess.run(
                    ["schtasks", "/query", "/fo", "CSV"],
                    capture_output=True, text=True, timeout=10
                )
                lines = r.stdout.splitlines()
                tasks = lines[:50]
            except Exception:
                pass
        elif SYSTEM == "Linux":
            cron_files = []
            for path in ["/etc/crontab", "/var/spool/cron/"]:
                try:
                    if os.path.isfile(path):
                        with open(path) as f:
                            cron_files.append(f.read()[:2000])
                    elif os.path.isdir(path):
                        for fn in os.listdir(path)[:10]:
                            with open(os.path.join(path, fn)) as f:
                                cron_files.append(f.read()[:1000])
                except Exception:
                    pass
            tasks = cron_files
        return tasks

    def _collect_environment(self) -> dict:
        """Snapshot current process environment (not target)."""
        return dict(list(os.environ.items())[:60])

    def _collect_shell_history(self) -> dict:
        history = {}
        home = Path.home()
        for hfile in [".bash_history", ".zsh_history", ".sh_history",
                      "AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"]:
            path = home / hfile
            try:
                if path.exists():
                    with open(path) as f:
                        lines = f.readlines()
                    history[hfile] = [l.strip() for l in lines[-100:] if l.strip()]
            except Exception:
                pass
        return history

    def _collect_recent_files(self) -> list:
        """Files modified in the last 60 seconds — shallow scan to avoid timeout."""
        recent = []
        watch_dirs = [str(Path.home()), os.getcwd()]
        if SYSTEM == "Linux":
            watch_dirs += ["/tmp", "/var/tmp"]
        cutoff = time.time() - 60

        # Skip deep dirs that cause timeouts on Windows
        SKIP_DIRS = {
            "AppData", "node_modules", ".git", "__pycache__",
            "site-packages", "Windows", "Program Files",
        }

        for d in watch_dirs:
            try:
                # Only walk 2 levels deep to avoid hanging on large dirs
                depth = 0
                for root, dirs, files in os.walk(d):
                    # Limit depth
                    rel = os.path.relpath(root, d)
                    depth = 0 if rel == "." else rel.count(os.sep) + 1
                    if depth > 2:
                        dirs.clear()
                        continue
                    # Skip known noisy dirs
                    dirs[:] = [dd for dd in dirs if dd not in SKIP_DIRS]
                    for fn in files[:10]:
                        fp = os.path.join(root, fn)
                        try:
                            mt = os.path.getmtime(fp)
                            if mt > cutoff:
                                recent.append({
                                    "path":     fp,
                                    "modified": datetime.fromtimestamp(mt).isoformat(),
                                    "size":     os.path.getsize(fp),
                                })
                        except Exception:
                            pass
                    if len(recent) > 100:
                        break
            except Exception:
                pass
        return recent[:100]

    def _collect_disk_usage(self) -> list:
        if not PSUTIL:
            return []
        disks = []
        try:
            for part in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    disks.append({
                        "device":     part.device,
                        "mountpoint": part.mountpoint,
                        "fstype":     part.fstype,
                        "total_gb":   round(usage.total / 1e9, 1),
                        "used_gb":    round(usage.used / 1e9, 1),
                        "free_gb":    round(usage.free / 1e9, 1),
                        "percent":    usage.percent,
                    })
                except Exception:
                    pass
        except Exception:
            pass
        return disks


class ForensicEngine:
    ENGINE = "ForensicEngine"

    def __init__(self, forensics_dir: str = "/tmp/sentinel_forensics"):
        self._dir = forensics_dir
        os.makedirs(forensics_dir, exist_ok=True)

    def collect(self, trigger: str, pid: Optional[int] = None,
                alert_info: dict = None) -> str:
        """
        Collect full forensic snapshot.
        Returns path to ZIP archive.
        """
        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        name     = f"forensics_{trigger.lower()[:20]}_{ts}"
        zip_path = os.path.join(self._dir, f"{name}.zip")

        log.info(f"Collecting forensics: {trigger} PID={pid}")

        snapshot = ForensicSnapshot(trigger=trigger, pid=pid)
        snapshot.collect_all()

        # Add alert info if provided
        if alert_info:
            snapshot.data["triggering_alert"] = alert_info

        manifest = {
            "sentinel_edr_version": "1.0.0",
            "collected_at":  snapshot.timestamp,
            "host":          snapshot.host,
            "os":            snapshot.os,
            "trigger":       trigger,
            "target_pid":    pid,
            "sections":      list(snapshot.data.keys()),
        }

        try:
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("manifest.json",
                            json.dumps(manifest, indent=2, default=str))
                for section, data in snapshot.data.items():
                    zf.writestr(
                        f"{section}.json",
                        json.dumps(data, indent=2, default=str)
                    )
            size_kb = os.path.getsize(zip_path) // 1024
            log.info(f"Forensics saved: {zip_path} ({size_kb} KB, "
                     f"{len(snapshot.data)} sections)")
            return zip_path
        except Exception as e:
            log.error(f"Forensics collection error: {e}")
            return ""

    def list_archives(self) -> list:
        archives = []
        try:
            for fn in sorted(os.listdir(self._dir), reverse=True):
                if fn.endswith(".zip"):
                    fp = os.path.join(self._dir, fn)
                    archives.append({
                        "file":     fn,
                        "path":     fp,
                        "size_kb":  os.path.getsize(fp) // 1024,
                        "created":  datetime.fromtimestamp(
                            os.path.getctime(fp)
                        ).isoformat(),
                    })
        except Exception:
            pass
        return archives
