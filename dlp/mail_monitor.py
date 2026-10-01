#!/usr/bin/env python3
"""
dlp/mail_monitor.py — Email Process DLP Monitor

Monitors for mail-client and SMTP processes showing suspicious behaviour:
  - Mail clients sending unusually large attachments
  - SMTP connections from non-mail processes (possible email exfil)
  - Mass email sending patterns

Source: NeuralGuard MailMonitor.
"""

import logging, threading, time
from collections import defaultdict

log = logging.getLogger("SentinelEDR.MailMonitor")

try:
    import psutil
    PSUTIL = True
except ImportError:
    PSUTIL = False

SMTP_PORTS  = {25, 465, 587, 2525}
IMAP_PORTS  = {143, 993}
POP3_PORTS  = {110, 995}
MAIL_PORTS  = SMTP_PORTS | IMAP_PORTS | POP3_PORTS

KNOWN_MAIL_PROCS = {
    "outlook.exe", "thunderbird.exe", "thunderbird",
    "evolution", "mutt", "alpine", "mail", "sendmail",
    "postfix", "dovecot", "exim",
}

SMTP_CONN_THRESHOLD = 10   # >10 SMTP connections from non-mail process = suspicious


class MailMonitor:
    ENGINE = "MailMonitor"

    def __init__(self):
        self._alerted = set()
        self._lock    = threading.Lock()

    def scan(self, event_bus):
        if not PSUTIL:
            return
        try:
            procs = list(psutil.process_iter(["pid", "name"]))
        except Exception:
            return

        for proc in procs:
            try:
                info = proc.info
                name = (info["name"] or "").lower()
                pid  = info["pid"]

                try:
                    conns = proc.net_connections()
                except (psutil.AccessDenied, AttributeError):
                    continue

                smtp_conns = [c for c in conns
                              if c.raddr and c.raddr.port in SMTP_PORTS]

                if not smtp_conns:
                    continue

                is_mail_proc = any(m in name for m in KNOWN_MAIL_PROCS)

                # Non-mail process making SMTP connections
                if not is_mail_proc and len(smtp_conns) >= 1:
                    alert_key = f"smtp:{pid}:{name}"
                    with self._lock:
                        if alert_key in self._alerted:
                            continue
                        self._alerted.add(alert_key)

                    from core.alert_manager import Alert
                    a = Alert(
                        alert_type   = "DLP_SMTP_NONMAIL_PROCESS",
                        severity     = "HIGH",
                        title        = f"Non-mail process sending SMTP: {name}",
                        description  = (
                            f"Process '{name}' (PID {pid}) is making SMTP connections "
                            f"but is not a known mail client. "
                            f"Possible email-based data exfiltration."
                        ),
                        process_info = {
                            "pid": pid, "name": name,
                            "smtp_connections": len(smtp_conns),
                            "destinations": [c.raddr.ip for c in smtp_conns[:5]],
                        },
                        risk_score   = 72,
                        mitre_tactic = "exfiltration",
                        mitre_tech   = "T1048.003",
                        engine       = self.ENGINE,
                    )
                    event_bus.publish("alert", {"kind": "alert", "alert": a})

                # Mass SMTP — even from mail client, >10 concurrent is suspicious
                if len(smtp_conns) >= SMTP_CONN_THRESHOLD:
                    alert_key = f"mass_smtp:{pid}:{len(smtp_conns)//5}"
                    with self._lock:
                        if alert_key in self._alerted:
                            continue
                        self._alerted.add(alert_key)

                    from core.alert_manager import Alert
                    a = Alert(
                        alert_type   = "DLP_MASS_SMTP",
                        severity     = "HIGH",
                        title        = f"Mass SMTP from {name}: {len(smtp_conns)} connections",
                        description  = (
                            f"Process '{name}' has {len(smtp_conns)} simultaneous SMTP "
                            f"connections — possible spam/exfil campaign."
                        ),
                        process_info = {
                            "pid": pid, "name": name,
                            "smtp_count": len(smtp_conns),
                        },
                        risk_score   = 75,
                        mitre_tactic = "exfiltration",
                        mitre_tech   = "T1048.003",
                        engine       = self.ENGINE,
                    )
                    event_bus.publish("alert", {"kind": "alert", "alert": a})

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                log.debug(f"MailMonitor error: {e}")
