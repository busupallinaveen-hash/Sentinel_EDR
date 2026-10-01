#!/usr/bin/env python3
"""
intel/mitre_mapper.py — MITRE ATT&CK Mapper + Navigator Export

Maps every SentinelEDR alert type to MITRE ATT&CK techniques.
Generates ATT&CK Navigator heatmap JSON for visualization.

Source: NeuralGuard MITREMapper, extended with IDPS techniques.
"""

import json, logging, os, time
from datetime import datetime
from typing import List, Optional

log = logging.getLogger("SentinelEDR.MITREMapper")

# ── Full technique mapping ─────────────────────────────────────────────────────
# Format: alert_type → [(tactic, technique_id, technique_name)]

ATTACK_MAPPING = {
    # Core behavioral
    "BEHAVIORAL_ANOMALY":          [("Defense Evasion",   "T1036", "Masquerading")],
    "SUSPICIOUS_PROCESS_CHAIN":    [("Execution",         "T1059", "Command and Scripting Interpreter")],
    "LOLBIN_ABUSE":                [("Defense Evasion",   "T1218", "System Binary Proxy Execution"),
                                    ("Execution",         "T1059", "Command and Scripting Interpreter")],
    "TEMPORAL_ANOMALY":            [("Defense Evasion",   "T1036", "Masquerading")],

    # Ransomware
    "RANSOMWARE_ENTROPY":          [("Impact",            "T1486", "Data Encrypted for Impact")],
    "RANSOMWARE_VELOCITY":         [("Impact",            "T1486", "Data Encrypted for Impact")],

    # Honeypot
    "HONEYPOT_FILE_ACCESS":        [("Credential Access", "T1552", "Unsecured Credentials"),
                                    ("Discovery",         "T1083", "File and Directory Discovery")],
    "HONEYPOT_NETWORK_HIT":        [("Discovery",         "T1046", "Network Service Discovery")],

    # Attack chains
    "ATTACK_CHAIN_DETECTED":       [("Lateral Movement",  "T1021", "Remote Services"),
                                    ("Execution",         "T1059", "Command and Scripting Interpreter")],

    # ML detections
    "ML_ANOMALY_ISOLATION_FOREST": [("Defense Evasion",   "T1036", "Masquerading")],
    "GNN_LATERAL_MOVEMENT":        [("Lateral Movement",  "T1021", "Remote Services"),
                                    ("Command and Control","T1071","Application Layer Protocol")],

    # Sigma rules
    "SIGMA_SIG-001":  [("Execution",          "T1059.001", "PowerShell")],
    "SIGMA_SIG-002":  [("Execution",          "T1059.001", "PowerShell"),
                       ("Command and Control","T1105",     "Ingress Tool Transfer")],
    "SIGMA_SIG-003":  [("Defense Evasion",    "T1218.005", "Mshta")],
    "SIGMA_SIG-004":  [("Defense Evasion",    "T1218.010", "Regsvr32")],
    "SIGMA_SIG-005":  [("Defense Evasion",    "T1140",     "Deobfuscate/Decode Files")],
    "SIGMA_SIG-006":  [("Defense Evasion",    "T1218.011", "Rundll32")],
    "SIGMA_SIG-007":  [("Execution",          "T1047",     "Windows Management Instrumentation")],
    "SIGMA_SIG-010":  [("Persistence",        "T1053.005", "Scheduled Task")],
    "SIGMA_SIG-011":  [("Persistence",        "T1547.001", "Registry Run Keys")],
    "SIGMA_SIG-020":  [("Credential Access",  "T1003.001", "LSASS Memory")],
    "SIGMA_SIG-021":  [("Credential Access",  "T1003.002", "Security Account Manager")],
    "SIGMA_SIG-040":  [("Lateral Movement",   "T1021.002", "SMB/Windows Admin Shares")],
    "SIGMA_SIG-050":  [("Defense Evasion",    "T1070.001", "Clear Windows Event Logs")],
    "SIGMA_SIG-051":  [("Defense Evasion",    "T1562.001", "Disable or Modify Tools")],
    "SIGMA_SIG-062":  [("Exfiltration",       "T1567.002", "Exfiltration to Cloud Storage")],
    "SIGMA_SIG-080":  [("Initial Access",     "T1204.002", "Malicious File")],
    "SIGMA_SIG-081":  [("Privilege Escalation","T1548.002", "Bypass User Account Control")],
    "SIGMA_SIG-082":  [("Defense Evasion",    "T1197",     "BITS Jobs")],
    "SIGMA_SIG-083":  [("Defense Evasion",    "T1562.001", "Disable or Modify Tools")],
    "SIGMA_SIG-084":  [("Persistence",        "T1546.003", "WMI Event Subscription")],
    "SIGMA_SIG-085":  [("Credential Access",  "T1558.003", "Kerberoasting")],
    "SIGMA_SIG-086":  [("Lateral Movement",   "T1021.002", "SMB/Windows Admin Shares")],
    "SIGMA_SIG-087":  [("Collection",         "T1113",     "Screen Capture")],

    # DLP
    "USB_DEVICE_INSERTED":         [("Exfiltration",      "T1052.001", "Exfiltration over USB")],
    "DLP_SMTP_NONMAIL_PROCESS":    [("Exfiltration",      "T1048.003", "Exfiltration Over Unencrypted Protocol")],
    "DLP_MASS_SMTP":               [("Exfiltration",      "T1048.003", "Exfiltration Over Unencrypted Protocol")],
    "DLP_EXFIL_DOMAIN":            [("Exfiltration",      "T1567",     "Exfiltration to Web Service")],
    "C2_BEACONING":                [("Command and Control","T1071",    "Application Layer Protocol")],
    "SUSPICIOUS_TLD_CONNECTION":   [("Command and Control","T1071",    "Application Layer Protocol")],
}


# ── Canonical Enterprise ATT&CK tactic order (kill-chain order) ────────────────
TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]


def technique_catalog() -> dict:
    """
    Flatten ATTACK_MAPPING into {technique_id: {"tactic": ..., "name": ...}}
    for every technique/sub-technique id SentinelEDR can emit. Used by the
    dashboard to render a tactic-column ATT&CK heatmap without duplicating
    the mapping client-side.
    """
    catalog = {}
    for entries in ATTACK_MAPPING.values():
        for tactic, tid, tname in entries:
            catalog[tid] = {"tactic": tactic, "name": tname}
    return catalog


def get_techniques(alert_type: str) -> List[dict]:
    """Return list of MITRE techniques for an alert type."""
    entries = ATTACK_MAPPING.get(alert_type, [])
    return [{"tactic": t, "technique_id": tid, "technique_name": tname}
            for t, tid, tname in entries]


def export_navigator_heatmap(alert_counts: dict, output_path: str) -> str:
    """
    Generate MITRE ATT&CK Navigator layer JSON from alert counts.
    Open at https://mitre-attack.github.io/attack-navigator/
    """
    technique_scores = {}
    for alert_type, count in alert_counts.items():
        for t, tid, tname in ATTACK_MAPPING.get(alert_type, []):
            base_tid = tid.split(".")[0]
            technique_scores[base_tid] = technique_scores.get(base_tid, 0) + count

    max_score = max(technique_scores.values(), default=1)

    techniques = []
    for tid, score in technique_scores.items():
        normalized = min(100, int(score / max_score * 100))
        techniques.append({
            "techniqueID": tid,
            "score":       normalized,
            "color":       "",
            "comment":     f"{score} alert(s)",
            "enabled":     True,
            "metadata":    [],
            "showSubtechniques": False,
        })

    layer = {
        "name":        f"SentinelEDR — {datetime.now().strftime('%Y-%m-%d')}",
        "versions":    {"attack": "14", "navigator": "4.9", "layer": "4.5"},
        "domain":      "enterprise-attack",
        "description": f"SentinelEDR alert heatmap — {sum(alert_counts.values())} total alerts",
        "filters":     {"platforms": ["Windows", "Linux", "macOS"]},
        "sorting":     3,
        "layout":      {"layout": "side", "aggregateFunction": "max",
                        "showID": True, "showName": True},
        "hideDisabled":False,
        "techniques":  techniques,
        "gradient":    {"colors": ["#ffffff", "#ff6666"], "minValue": 0, "maxValue": 100},
        "legendItems": [],
        "metadata":    [],
        "links":       [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
    }

    with open(output_path, "w") as f:
        json.dump(layer, f, indent=2)

    log.info(f"ATT&CK Navigator heatmap exported: {output_path}")
    return output_path
