#!/usr/bin/env python3
"""
integrations/notifier.py — Desktop Notification Engine

Subscribes to the event bus and raises a native OS desktop notification
whenever an alert crosses a configurable severity threshold.

Deliberately zero new pip dependencies — SentinelEDR's core already runs on
just psutil + watchdog, so this shells out to whatever notification tool the
OS already ships with, the same way response_engine.py shells out to
iptables/netsh/pfctl rather than pulling in a firewall library:
  - Windows : a short PowerShell script using System.Windows.Forms.NotifyIcon
              (a balloon-tip notification). Chosen over the newer Toast/
              Windows.UI.Notifications API because that API requires the
              calling process to have a registered AUMID (app identity) to
              reliably surface in the Action Center — a balloon tip has no
              such requirement and works from a plain script.
  - Linux   : notify-send (part of libnotify, present on essentially every
              desktop Linux distribution).
  - macOS   : osascript's `display notification`.

If the underlying OS tool isn't present, or if there's no desktop session at
all (a headless server), notifications fail closed: logged once, then
silently skipped — never allowed to crash or block detection.
"""

import logging, platform, subprocess, threading, time

log = logging.getLogger("SentinelEDR.Notifier")

SYSTEM = platform.system()

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class NotificationEngine:
    """
    handle(event) is the event-bus callback (same shape every other
    subscriber in this codebase uses — see alert_manager.handle,
    SIEMRouter.handle). config is the parsed sentinel.yaml dict.
    """

    def __init__(self, config: dict):
        ncfg = (config or {}).get("notifications", {}).get("desktop", {})
        self._enabled       = ncfg.get("enabled", True)
        self._min_severity  = ncfg.get("min_severity", "HIGH").upper()
        self._min_rank      = SEVERITY_RANK.get(self._min_severity, 3)
        self._rate_limit_s  = ncfg.get("rate_limit_seconds", 5)
        self._lock          = threading.Lock()
        self._last_sent_at  = 0.0
        self._warned_missing_tool = False

        if not self._enabled:
            log.info("Desktop notifications disabled (notifications.enabled: false)")

    def handle(self, event: dict):
        """EventBus callback — receives raw alert dicts, same as AlertManager.handle."""
        if not self._enabled or event.get("kind") != "alert":
            return
        alert = event.get("alert")
        if alert is None:
            return

        severity = getattr(alert, "severity", "LOW")
        if SEVERITY_RANK.get(severity, 0) < self._min_rank:
            return  # below the configured threshold — stay quiet

        with self._lock:
            now = time.time()
            if now - self._last_sent_at < self._rate_limit_s:
                # A burst of alerts (e.g. an attack chain firing several
                # rules within a second) shouldn't spawn a stack of popups —
                # the dashboard is the place to see all of them; the
                # notification is just "look now", not a full feed.
                return
            self._last_sent_at = now

        engine = getattr(alert, "engine", "SentinelEDR")
        title = f"SentinelEDR — {severity}"
        message = f"[{engine}] {getattr(alert, 'title', 'Alert')}"
        self._send(title, message)

    # -- platform dispatch ---------------------------------------------------

    def _send(self, title: str, message: str):
        try:
            if SYSTEM == "Windows":
                self._send_windows(title, message)
            elif SYSTEM == "Linux":
                self._send_linux(title, message)
            elif SYSTEM == "Darwin":
                self._send_macos(title, message)
            else:
                self._warn_once(f"Unsupported platform for notifications: {SYSTEM}")
        except FileNotFoundError:
            self._warn_once(
                "No desktop notification tool found on this system "
                "(notify-send/osascript/PowerShell) — skipping notifications."
            )
        except Exception as e:
            self._warn_once(f"Desktop notification failed: {e}")

    def _warn_once(self, msg: str):
        if not self._warned_missing_tool:
            log.warning(msg)
            self._warned_missing_tool = True

    @staticmethod
    def _ps_escape(text: str) -> str:
        # Inside a single-quoted PowerShell string, a literal single quote
        # is escaped by doubling it.
        return (text or "").replace("'", "''")

    def _send_windows(self, title: str, message: str):
        t, m = self._ps_escape(title), self._ps_escape(message)
        script = (
            "Add-Type -AssemblyName System.Windows.Forms; "
            "Add-Type -AssemblyName System.Drawing; "
            "$n = New-Object System.Windows.Forms.NotifyIcon; "
            "$n.Icon = [System.Drawing.SystemIcons]::Warning; "
            "$n.Visible = $true; "
            f"$n.ShowBalloonTip(5000, '{t}', '{m}', "
            "[System.Windows.Forms.ToolTipIcon]::Warning); "
            "Start-Sleep -Seconds 6; "
            "$n.Dispose()"
        )
        # CREATE_NO_WINDOW (not just -WindowStyle Hidden) matters here: Windows
        # still briefly allocates a console for a "hidden" PowerShell process
        # before it processes that flag, and because this child is spawned
        # from the currently-foreground SentinelEDR console, the OS's
        # foreground-activation rules let that brief window steal focus —
        # felt as the active window/tab flipping every time a notification
        # fires. CREATE_NO_WINDOW tells the OS never to allocate a console
        # for the process at all, so there's nothing to steal focus with.
        subprocess.Popen(
            ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", script],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )

    def _send_linux(self, title: str, message: str):
        subprocess.Popen(
            ["notify-send", "--urgency=critical", title, message],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    def _send_macos(self, title: str, message: str):
        def esc(text):
            return (text or "").replace("\\", "\\\\").replace('"', '\\"')
        script = f'display notification "{esc(message)}" with title "{esc(title)}"'
        subprocess.Popen(
            ["osascript", "-e", script],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
