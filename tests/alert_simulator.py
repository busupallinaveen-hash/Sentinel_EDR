#!/usr/bin/env python3
"""
tests/alert_simulator.py — Attack Scenario Simulator

Fires realistic synthetic attack scenarios through SentinelEDR engines.
Used to:
  1. Verify all detection engines are working
  2. Test response engine actions (in dry-run mode)
  3. Generate demo alerts for dashboard testing
  4. Regression test after code changes

Run with:
  python tests/alert_simulator.py                  # all scenarios
  python tests/alert_simulator.py --scenario ransom # specific scenario
  python tests/alert_simulator.py --dashboard       # pump alerts for dashboard demo
"""

import argparse, json, logging, os, sys, time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("SentinelEDR.Simulator")

from core.alert_manager import Alert, AlertManager
from core.event_bus import EventBus

SCENARIOS = {}

def scenario(name):
    def decorator(fn):
        SCENARIOS[name] = fn
        return fn
    return decorator


def _emit(mgr, bus, alert_type, severity, title, description,
          risk_score=70, mitre_tech=None, mitre_tactic=None,
          engine="Simulator", process_info=None):
    a = Alert(
        alert_type=alert_type, severity=severity, title=title,
        description=description, risk_score=risk_score,
        mitre_tech=mitre_tech, mitre_tactic=mitre_tactic,
        engine=engine, process_info=process_info or {},
    )
    mgr.add(a)
    bus.publish("alert", {"kind": "alert", "alert": a})
    log.info(f"  [{severity}] {title}")
    time.sleep(0.2)
    return a


@scenario("ransomware")
def sim_ransomware(mgr, bus):
    """Simulate a ransomware attack chain."""
    log.info("▶ Scenario: Ransomware Attack Chain")
    _emit(mgr, bus, "RANSOMWARE_ENTROPY", "CRITICAL",
          "High-entropy file write: documents.docx.locked",
          "File written with entropy 7.89/8.0 — ransomware encryption detected",
          risk_score=95, mitre_tech="T1486", mitre_tactic="impact",
          process_info={"path": "/home/user/documents.docx.locked", "entropy": 7.89})
    _emit(mgr, bus, "RANSOMWARE_VELOCITY", "CRITICAL",
          "High file-write velocity: 45 files/min",
          "45 files written in 60s — mass encryption in progress",
          risk_score=98, mitre_tech="T1486", mitre_tactic="impact",
          process_info={"writes_per_minute": 45})
    _emit(mgr, bus, "ATTACK_CHAIN_DETECTED", "CRITICAL",
          "Attack chain: Download cradle → Execute → C2 connect",
          "Staged payload: PowerShell downloaded and executed dropper, then connected to C2",
          risk_score=92, mitre_tech="T1059.001", mitre_tactic="execution")


@scenario("lateral_movement")
def sim_lateral(mgr, bus):
    """Simulate lateral movement attack."""
    log.info("▶ Scenario: Lateral Movement")
    _emit(mgr, bus, "SIGMA_SIG-020", "CRITICAL",
          "[SIG-020] LSASS memory access",
          "Process 'procdump.exe' accessing LSASS — credential dump attempt",
          risk_score=95, mitre_tech="T1003.001", mitre_tactic="credential_access",
          process_info={"pid": 4512, "name": "procdump.exe", "cmdline": "procdump -ma lsass"})
    _emit(mgr, bus, "ATTACK_CHAIN_DETECTED", "CRITICAL",
          "Attack chain: Credential dump → Lateral movement",
          "LSASS accessed followed by network logon — classic dump-and-move sequence",
          risk_score=92, mitre_tech="T1021.002", mitre_tactic="lateral_movement")
    _emit(mgr, bus, "GNN_LATERAL_MOVEMENT", "HIGH",
          "GNN: suspicious connection graph — svchost.exe",
          "Process 'svchost.exe' has anomalous connection graph (score=0.87) connecting to 10.0.0.55:445",
          risk_score=75, mitre_tech="T1021", mitre_tactic="lateral_movement",
          process_info={"pid": 832, "name": "svchost.exe", "remote_ip": "10.0.0.55",
                        "remote_port": 445, "graph_score": 0.87})


@scenario("powershell_attack")
def sim_powershell(mgr, bus):
    """Simulate PowerShell-based attack."""
    log.info("▶ Scenario: PowerShell Attack")
    _emit(mgr, bus, "LOLBIN_ABUSE", "CRITICAL",
          "LOLBin pattern: powershell.exe",
          "PowerShell IEX download cradle detected: IEX(New-Object Net.WebClient).DownloadString",
          risk_score=90, mitre_tech="T1059.001", mitre_tactic="execution",
          process_info={"pid": 2048, "name": "powershell.exe",
                        "cmdline": "powershell.exe -enc SQBFAFgA..."})
    _emit(mgr, bus, "SIGMA_SIG-002", "CRITICAL",
          "[SIG-002] PowerShell download cradle",
          "PowerShell downloading and executing: DownloadString detected",
          risk_score=90, mitre_tech="T1059.001", mitre_tactic="execution")
    _emit(mgr, bus, "SUSPICIOUS_PROCESS_CHAIN", "HIGH",
          "Suspicious chain: winword.exe → powershell.exe",
          "Word spawned PowerShell — macro execution | PID 1234 → 2048",
          risk_score=85, mitre_tech="T1566.001", mitre_tactic="execution")


@scenario("honeypot")
def sim_honeypot(mgr, bus):
    """Simulate honeypot trigger."""
    log.info("▶ Scenario: Honeypot Triggered")
    _emit(mgr, bus, "HONEYPOT_FILE_ACCESS", "CRITICAL",
          "Honeypot accessed: .sentinel_decoy_credentials.json",
          "Decoy credential file touched by python3 (PID 8821). Zero-FP indicator of credential hunting.",
          risk_score=97, mitre_tech="T1552", mitre_tactic="credential_access",
          process_info={"path": str(Path.home() / ".sentinel_decoy_credentials.json"),
                        "event": "modified", "accessor": "python3 (PID 8821)"})
    _emit(mgr, bus, "HONEYPOT_NETWORK_HIT", "CRITICAL",
          "Network honeypot hit: SSH port 2222",
          "Attacker 192.168.1.100:54321 connected to fake SSH service. Zero-FP.",
          risk_score=98, mitre_tech="T1046", mitre_tactic="discovery",
          process_info={"attacker_ip": "192.168.1.100", "attacker_port": 54321,
                        "honeypot_port": 2222, "service": "SSH"})


@scenario("exfiltration")
def sim_exfil(mgr, bus):
    """Simulate data exfiltration."""
    log.info("▶ Scenario: Data Exfiltration")
    _emit(mgr, bus, "DLP_EXFIL_DOMAIN", "HIGH",
          "Connection to exfil site: transfer.sh",
          "Active connection to transfer.sh (1.2.3.4) — possible data theft in progress",
          risk_score=80, mitre_tech="T1567", mitre_tactic="exfiltration",
          process_info={"remote_ip": "1.2.3.4", "hostname": "transfer.sh"})
    _emit(mgr, bus, "USB_DEVICE_INSERTED", "MEDIUM",
          "USB device inserted: /dev/sdb",
          "Removable storage /dev/sdb connected — monitor for data exfiltration",
          risk_score=45, mitre_tech="T1052.001", mitre_tactic="exfiltration")
    _emit(mgr, bus, "SIGMA_SIG-062", "CRITICAL",
          "[SIG-062] Rclone sync to cloud — exfiltration",
          "rclone copy to remote cloud storage — possible data exfiltration",
          risk_score=90, mitre_tech="T1567.002", mitre_tactic="exfiltration",
          process_info={"pid": 9123, "name": "rclone", "cmdline": "rclone copy /home/user s3:bucket"})


@scenario("defense_evasion")
def sim_evasion(mgr, bus):
    """Simulate defense evasion."""
    log.info("▶ Scenario: Defense Evasion")
    _emit(mgr, bus, "SIGMA_SIG-051", "CRITICAL",
          "[SIG-051] AV/Defender disabling",
          "PowerShell disabling Windows Defender: Set-MpPreference -DisableRealtimeMonitoring",
          risk_score=95, mitre_tech="T1562.001", mitre_tactic="defense_evasion",
          process_info={"pid": 3300, "name": "powershell.exe",
                        "cmdline": "Set-MpPreference -DisableRealtimeMonitoring $true"})
    _emit(mgr, bus, "SIGMA_SIG-050", "HIGH",
          "[SIG-050] Windows event log clearing",
          "wevtutil cl System — attacker clearing event logs to cover tracks",
          risk_score=85, mitre_tech="T1070.001", mitre_tactic="defense_evasion",
          process_info={"pid": 4400, "name": "wevtutil.exe", "cmdline": "wevtutil cl System"})
    _emit(mgr, bus, "AGENT_REPEATEDLY_KILLED", "CRITICAL",
          "SentinelEDR killed 3x — attacker disabling security",
          "Agent killed 3 times in 120s — T1562.001 pattern. Watchdog restarting.",
          risk_score=99, mitre_tech="T1562.001", mitre_tactic="defense_evasion")


@scenario("all")
def sim_all(mgr, bus):
    """Run all scenarios."""
    for name, fn in SCENARIOS.items():
        if name != "all":
            fn(mgr, bus)
            time.sleep(1)


def run_dashboard_pump(mgr, bus, duration_s: int = 60):
    """Continuously emit alerts for dashboard demo."""
    log.info(f"Dashboard pump: emitting alerts for {duration_s}s...")
    end = time.time() + duration_s
    cycle = 0
    while time.time() < end:
        cycle += 1
        scen = list(SCENARIOS.keys())
        scen.remove("all")
        fn = SCENARIOS[scen[cycle % len(scen)]]
        fn(mgr, bus)
        time.sleep(3)


def main():
    parser = argparse.ArgumentParser(description="SentinelEDR Attack Simulator")
    parser.add_argument("--scenario", default="all",
                        choices=list(SCENARIOS.keys()),
                        help="Which scenario to run")
    parser.add_argument("--dashboard", action="store_true",
                        help="Pump alerts continuously for dashboard demo")
    parser.add_argument("--duration", type=int, default=60,
                        help="Duration for --dashboard mode (seconds)")
    args = parser.parse_args()

    import tempfile, os
    alert_file = os.path.join(
        os.environ.get("TEMP") or os.environ.get("TMP") or tempfile.gettempdir(),
        "sentinel_alerts.json"
    )
    # Ensure parent directory exists
    os.makedirs(os.path.dirname(alert_file), exist_ok=True)
    mgr = AlertManager(alert_file)
    bus = EventBus()
    bus.subscribe("alert", mgr.handle)

    print(f"\n{'═'*55}")
    print("  SentinelEDR Attack Scenario Simulator")
    print(f"{'═'*55}\n")

    if args.dashboard:
        run_dashboard_pump(mgr, bus, args.duration)
    else:
        fn = SCENARIOS.get(args.scenario)
        if fn:
            fn(mgr, bus)
        else:
            print(f"Unknown scenario: {args.scenario}")

    print(f"\n{'═'*55}")
    print(f"  Done. Total alerts: {mgr.total()}")
    print(f"  Alert file: {alert_file}")
    print(f"{'═'*55}\n")


if __name__ == "__main__":
    main()
