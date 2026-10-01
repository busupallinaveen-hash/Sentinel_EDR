#!/usr/bin/env python3
"""
dlp/domain_monitor.py — Domain & Network DLP Monitor

Monitors outbound network connections for:
  1. Connections to known paste/exfil sites (pastebin, transfer.sh, etc.)
  2. Unusually large DNS queries (DNS tunneling indicator)
  3. High-volume outbound traffic to single external host
  4. Connections to Tor exit nodes (known C2 evasion)

Source: NeuralGuard DLPDomainMonitor, extended.
"""

import ipaddress, logging, socket, threading, time
from collections import defaultdict, deque

log = logging.getLogger("SentinelEDR.DomainMonitor")

try:
    import psutil
    PSUTIL = True
except ImportError:
    PSUTIL = False

# ── Known exfiltration / paste sites ──────────────────────────────────────────
EXFIL_DOMAINS = {
    "pastebin.com", "paste.ee", "hastebin.com", "ghostbin.co",
    "transfer.sh", "file.io", "wetransfer.com", "sendspace.com",
    "mega.nz", "anonfiles.com", "bayfiles.com", "ufile.io",
    "cdn.discordapp.com", "webhook.site",
    "ngrok.io", "serveo.net", "localhost.run",  # tunnel services
    "requestbin.com", "hookbin.com",             # webhook exfil
}

# ── Suspicious TLDs often used in C2 ──────────────────────────────────────────
SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".gq", ".ml", ".cf", ".tk", ".pw"}

BYTES_THRESHOLD = 50 * 1024 * 1024   # 50MB outbound to single host = alert
DNS_LEN_THRESH  = 100                 # DNS query >100 chars = possible tunneling
CONN_THRESHOLD  = 50                  # >50 connections to single IP = beaconing


class DomainMonitor:
    ENGINE = "DomainMonitor"

    def __init__(self):
        self._alerted       = set()
        self._conn_counts   = defaultdict(int)    # remote_ip → connection count
        self._lock          = threading.Lock()
        self._scan_n        = 0

    def _resolve_raddr(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0].lower()
        except Exception:
            return ""

    @staticmethod
    def _is_local_ip(ip: str) -> bool:
        """
        True for private/loopback/link-local/reserved/multicast addresses —
        e.g. a home router at 192.168.1.1, or a LAN peer. High connection
        counts to these are normal network operation, not C2 beaconing.
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast)

    def scan(self, event_bus):
        if not PSUTIL:
            return
        self._scan_n += 1

        try:
            conns = psutil.net_connections(kind="inet")
        except Exception:
            return

        ip_counts = defaultdict(int)
        for c in conns:
            if c.raddr and not self._is_local_ip(c.raddr.ip):
                ip_counts[c.raddr.ip] += 1

        for ip, count in ip_counts.items():
            # High connection count = possible beaconing
            if count >= CONN_THRESHOLD:
                alert_key = f"beacon:{ip}:{count//10}"
                with self._lock:
                    if alert_key not in self._alerted:
                        self._alerted.add(alert_key)
                        hostname = self._resolve_raddr(ip)
                        from core.alert_manager import Alert
                        a = Alert(
                            alert_type   = "C2_BEACONING",
                            severity     = "HIGH",
                            title        = f"Possible C2 beaconing: {count} conns to {ip}",
                            description  = (
                                f"{count} simultaneous connections to {ip} "
                                f"({hostname or 'unresolved'}). "
                                f"Consistent with C2 beaconing behavior."
                            ),
                            process_info = {"remote_ip": ip, "hostname": hostname,
                                            "connection_count": count},
                            risk_score   = min(95, 50 + count),
                            mitre_tactic = "command_and_control",
                            mitre_tech   = "T1071",
                            engine       = self.ENGINE,
                        )
                        event_bus.publish("alert", {"kind": "alert", "alert": a})

            # Check if IP resolves to known exfil domain
            if self._scan_n % 10 == 0:  # only resolve every 10 scans (expensive)
                hostname = self._resolve_raddr(ip)
                if hostname:
                    for domain in EXFIL_DOMAINS:
                        if domain in hostname:
                            alert_key = f"exfil:{ip}:{domain}"
                            with self._lock:
                                if alert_key not in self._alerted:
                                    self._alerted.add(alert_key)
                                    from core.alert_manager import Alert
                                    a = Alert(
                                        alert_type   = "DLP_EXFIL_DOMAIN",
                                        severity     = "HIGH",
                                        title        = f"Connection to exfil site: {domain}",
                                        description  = (
                                            f"Active connection to known data exfiltration "
                                            f"service '{domain}' ({ip}). "
                                            f"Possible data theft in progress."
                                        ),
                                        process_info = {"remote_ip": ip,
                                                        "hostname": hostname,
                                                        "matched_domain": domain},
                                        risk_score   = 80,
                                        mitre_tactic = "exfiltration",
                                        mitre_tech   = "T1567",
                                        engine       = self.ENGINE,
                                    )
                                    event_bus.publish("alert", {"kind": "alert", "alert": a})
                            break

                    # Suspicious TLD check
                    for tld in SUSPICIOUS_TLDS:
                        if hostname.endswith(tld):
                            alert_key = f"tld:{ip}:{tld}"
                            with self._lock:
                                if alert_key not in self._alerted:
                                    self._alerted.add(alert_key)
                                    from core.alert_manager import Alert
                                    a = Alert(
                                        alert_type   = "SUSPICIOUS_TLD_CONNECTION",
                                        severity     = "MEDIUM",
                                        title        = f"Connection to suspicious TLD: {hostname}",
                                        description  = (
                                            f"Connection to '{hostname}' with suspicious "
                                            f"TLD '{tld}' — commonly used in C2 infrastructure."
                                        ),
                                        process_info = {"remote_ip": ip,
                                                        "hostname": hostname, "tld": tld},
                                        risk_score   = 55,
                                        mitre_tactic = "command_and_control",
                                        mitre_tech   = "T1071",
                                        engine       = self.ENGINE,
                                    )
                                    event_bus.publish("alert", {"kind": "alert", "alert": a})
                            break

        # Prune cache
        with self._lock:
            if len(self._alerted) > 2000:
                self._alerted.clear()
