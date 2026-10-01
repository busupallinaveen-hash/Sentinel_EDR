#!/usr/bin/env python3
"""
dlp/usb_monitor.py — USB Device Monitor

Detects USB mass storage device insertion and monitors for
suspicious file copies to removable media.

Source: NeuralGuard USBMonitor.
"""

import logging, os, platform, threading, time
from collections import defaultdict

log    = logging.getLogger("SentinelEDR.USBMonitor")
SYSTEM = platform.system()

try:
    import psutil
    PSUTIL = True
except ImportError:
    PSUTIL = False


class USBMonitor:
    ENGINE = "USBMonitor"

    def __init__(self):
        self._known_partitions = set()
        self._alerted          = set()
        self._lock             = threading.Lock()
        self._initialized      = False

    def _get_removable_partitions(self) -> set:
        if not PSUTIL:
            return set()
        try:
            return {
                p.device for p in psutil.disk_partitions(all=False)
                if "removable" in p.opts.lower() or
                   (SYSTEM != "Windows" and "/media/" in p.mountpoint) or
                   (SYSTEM != "Windows" and "/run/media/" in p.mountpoint) or
                   (SYSTEM == "Darwin"  and "/Volumes/" in p.mountpoint and
                    p.mountpoint != "/Volumes/Macintosh HD")
            }
        except Exception:
            return set()

    def scan(self, event_bus):
        current = self._get_removable_partitions()

        if not self._initialized:
            self._known_partitions = current
            self._initialized = True
            return

        new_devices = current - self._known_partitions
        if new_devices:
            for dev in new_devices:
                alert_key = f"usb:{dev}:{int(time.time()//60)}"
                with self._lock:
                    if alert_key in self._alerted:
                        continue
                    self._alerted.add(alert_key)

                from core.alert_manager import Alert
                a = Alert(
                    alert_type   = "USB_DEVICE_INSERTED",
                    severity     = "MEDIUM",
                    title        = f"USB device inserted: {dev}",
                    description  = (
                        f"Removable storage device '{dev}' was connected. "
                        f"Monitor for data exfiltration via file copies to this device."
                    ),
                    process_info = {"device": dev, "known_before": False},
                    risk_score   = 45,
                    mitre_tactic = "exfiltration",
                    mitre_tech   = "T1052.001",
                    engine       = self.ENGINE,
                )
                event_bus.publish("alert", {"kind": "alert", "alert": a})
                log.warning(f"USB inserted: {dev}")

        self._known_partitions = current
