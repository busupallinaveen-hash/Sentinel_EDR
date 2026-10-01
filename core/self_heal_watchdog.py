#!/usr/bin/env python3
"""
core/self_heal_watchdog.py — Self-Healing Watchdog

Runs as a SEPARATE process that monitors the main SentinelEDR agent.
If the agent is killed or crashes, the watchdog restarts it automatically.

This defeats the common attacker technique of killing security software
before deploying payload (T1562.001 — Disable or Modify Tools).

Usage:
  python core/self_heal_watchdog.py --agent sentinel.py [--args "--dry-run"]

The watchdog:
  1. Spawns sentinel.py as a child process
  2. Monitors it every 5 seconds
  3. Restarts it if it exits or is killed
  4. Logs all restart events
  5. Alerts on repeated kills (attacker pattern)
  6. Writes its own PID to watchdog.pid so it can be stopped cleanly
"""

import argparse, logging, os, platform, signal, subprocess, sys, time
from datetime import datetime
from pathlib import Path

log    = logging.getLogger("SentinelEDR.Watchdog")
SYSTEM = platform.system()

PID_FILE        = Path("/tmp/sentinel_watchdog.pid")
RESTART_LOG     = Path("/tmp/sentinel_watchdog.log")
MAX_RESTARTS    = 10          # max restarts in RESTART_WINDOW before pausing
RESTART_WINDOW  = 300         # 5-minute window for restart counting
RESTART_PAUSE   = 60          # pause between restarts after rapid kills
KILL_ALERT_THRESH = 3         # alert after this many kills in the window


def _write_pid():
    PID_FILE.write_text(str(os.getpid()))


def _log_restart(reason: str, restart_count: int):
    ts  = datetime.now().isoformat()
    msg = f"{ts} | PID {os.getpid()} | restart #{restart_count} | {reason}\n"
    try:
        with open(RESTART_LOG, "a") as f:
            f.write(msg)
    except Exception:
        pass
    log.warning(f"[WATCHDOG] {msg.strip()}")


def _alert_repeated_kills(count: int):
    """Write a high-priority alert when the agent is killed repeatedly."""
    alert = {
        "timestamp":   datetime.now().isoformat(),
        "type":        "AGENT_REPEATEDLY_KILLED",
        "severity":    "CRITICAL",
        "title":       f"SentinelEDR killed {count}x — attacker disabling security",
        "description": (
            f"SentinelEDR agent was killed {count} times in {RESTART_WINDOW}s. "
            f"This is consistent with T1562.001 (Disable or Modify Tools). "
            f"The watchdog has restarted the agent."
        ),
        "risk_score": 99,
        "engine":     "SelfHealWatchdog",
    }
    import json
    alert_file = "/tmp/sentinel_alerts.json"
    try:
        existing = []
        if os.path.exists(alert_file):
            with open(alert_file) as f:
                existing = json.load(f)
        existing.append(alert)
        with open(alert_file, "w") as f:
            json.dump(existing[-5000:], f, indent=2)
    except Exception:
        pass
    log.critical(f"🔴 WATCHDOG ALERT: {alert['title']}")


class Watchdog:
    def __init__(self, agent_script: str, agent_args: list,
                 python_exe: str = sys.executable):
        self._agent      = agent_script
        self._args       = agent_args
        self._python     = python_exe
        self._proc       = None
        self._running    = True
        self._restarts   = []     # timestamps of restarts
        self._total      = 0

        signal.signal(signal.SIGTERM, self._stop)
        signal.signal(signal.SIGINT,  self._stop)

    def _stop(self, sig, frame):
        log.info("[WATCHDOG] Stopping watchdog...")
        self._running = False
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
            except Exception:
                pass
        if PID_FILE.exists():
            PID_FILE.unlink()
        sys.exit(0)

    def _spawn(self) -> subprocess.Popen:
        cmd = [self._python, self._agent] + self._args
        log.info(f"[WATCHDOG] Spawning: {' '.join(cmd)}")
        return subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

    def _recent_restarts(self) -> int:
        cutoff = time.time() - RESTART_WINDOW
        self._restarts = [t for t in self._restarts if t > cutoff]
        return len(self._restarts)

    def run(self):
        _write_pid()
        log.info(f"[WATCHDOG] Starting — PID {os.getpid()}")
        log.info(f"[WATCHDOG] Monitoring: {self._agent} {' '.join(self._args)}")

        self._proc = self._spawn()
        self._total += 1

        while self._running:
            time.sleep(5)

            if self._proc.poll() is not None:
                # Agent exited — get return code
                rc = self._proc.returncode
                reason = f"Exit code {rc}"
                if rc == -signal.SIGKILL if SYSTEM != "Windows" else rc != 0:
                    reason = f"KILLED (signal {abs(rc)})"

                self._restarts.append(time.time())
                recent = self._recent_restarts()
                self._total += 1

                _log_restart(reason, self._total)

                # Alert on repeated kills
                if recent >= KILL_ALERT_THRESH:
                    _alert_repeated_kills(recent)

                # Back-off if killing too fast
                if recent >= MAX_RESTARTS:
                    log.warning(f"[WATCHDOG] {recent} restarts in {RESTART_WINDOW}s — "
                                f"pausing {RESTART_PAUSE}s")
                    time.sleep(RESTART_PAUSE)

                self._proc = self._spawn()


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(str(RESTART_LOG), mode="a"),
            logging.StreamHandler(sys.stdout),
        ],
    )

    parser = argparse.ArgumentParser(
        description="SentinelEDR Self-Healing Watchdog"
    )
    parser.add_argument(
        "--agent", default="sentinel.py",
        help="Path to sentinel.py agent script"
    )
    parser.add_argument(
        "--args", default="",
        help="Arguments to pass to the agent (e.g. '--dry-run --no-ml')"
    )
    parser.add_argument(
        "--python", default=sys.executable,
        help="Python executable to use"
    )
    parser.add_argument(
        "--stop", action="store_true",
        help="Stop a running watchdog"
    )
    args = parser.parse_args()

    if args.stop:
        if PID_FILE.exists():
            pid = int(PID_FILE.read_text().strip())
            try:
                os.kill(pid, signal.SIGTERM)
                print(f"Watchdog PID {pid} stopped")
                PID_FILE.unlink()
            except ProcessLookupError:
                print(f"Watchdog PID {pid} not running")
                PID_FILE.unlink()
        else:
            print("No watchdog PID file found")
        return

    if PID_FILE.exists():
        pid = int(PID_FILE.read_text().strip())
        try:
            os.kill(pid, 0)
            print(f"Watchdog already running (PID {pid}). Use --stop to stop it.")
            return
        except ProcessLookupError:
            PID_FILE.unlink()

    agent_args = args.args.split() if args.args else []
    wdog = Watchdog(args.agent, agent_args, args.python)
    wdog.run()


if __name__ == "__main__":
    main()
