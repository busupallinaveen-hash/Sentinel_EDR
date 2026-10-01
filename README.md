# SentinelEDR v1.0
### The combined intelligence of NeuralGuard + IDPS — in one deployable tool.

```
╔══════════════════════════════════════════════════════════════════════════════╗
║   SentinelEDR v1.0  —  Unified Endpoint Detection & Response               ║
║   NeuralGuard's deployability × IDPS v7's detection depth                  ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## What is SentinelEDR?

SentinelEDR takes the best components from two separate open-source EDR projects and merges them into a single, coherent tool:

- **From NeuralGuard**: Cross-platform simplicity, behavioral DNA profiling, Shannon entropy ransomware detection, USB/email/DLP monitoring, honeypot file mesh, clean pluggable architecture
- **From IDPS v7**: GNN-based lateral movement detection, IsolationForest + ML anomaly engine, Sigma rules engine, multi-event behavioral chain correlation, response playbooks

**Core runs with 2 dependencies. Advanced ML features are opt-in plugins.**

---

## Quick Start

```bash
# Install core deps (2 packages)
pip install psutil watchdog --break-system-packages

# Run — full mode with all core engines
sudo python sentinel.py

# Lite mode — core engines only, no ML plugins
sudo python sentinel.py --lite

# Dry-run — detect but don't respond
sudo python sentinel.py --dry-run

# Self-test — verify all engines work
python sentinel.py --test

# Check alert summary
python sentinel.py --status

# List all available plugins
python sentinel.py --list-plugins
```

**Optional: Install ML plugins for IsolationForest + GNN detection**
```bash
pip install numpy scikit-learn networkx --break-system-packages
```

---

## Detection Engines

| Engine | Source | What it detects | Deps |
|--------|--------|-----------------|------|
| **Behavioral DNA** | NeuralGuard | Z-score anomalies per (process, user) pair | psutil |
| **Process Ancestry** | NeuralGuard | LOLBin chains, office→shell, web→bash | psutil |
| **Entropy Shield** | NeuralGuard | Ransomware file encryption (Shannon entropy) | watchdog |
| **Temporal Anomaly** | NeuralGuard | Processes running at unusual hours | psutil |
| **Behavioral Chains** | IDPS v7 | Multi-event attack sequences (cred dump → lateral move) | psutil |
| **Sigma Engine** | IDPS v7 | 30+ signature rules (PowerShell, LOLBins, AD recon, etc.) | psutil |
| **IsolationForest ML** | IDPS v7 | Zero-day anomalies via unsupervised ML | numpy + sklearn |
| **GNN Graph Engine** | IDPS v7 | Lateral movement, multi-hop attack paths | numpy + networkx |
| **Honeypot Mesh** | Both | File + network decoys (zero false-positives) | watchdog |

---

## Response Actions

When a CRITICAL/HIGH alert fires, SentinelEDR responds automatically (unless `--dry-run`):

| Trigger | Response |
|---------|----------|
| Honeypot hit | Kill process + block attacker IP + collect forensics |
| Ransomware entropy/velocity | Kill process + quarantine file + collect forensics |
| Critical attack chain | Kill process + collect forensics |
| AV disable / LSASS access | Kill process |
| HIGH severity alert | Collect forensics snapshot |

Forensics snapshots include: process tree, open files, network connections, environment variables, memory info. Saved as `.zip` in the forensics directory.

---

## DLP Monitoring

| Monitor | What it watches |
|---------|-----------------|
| **USB Monitor** | Removable storage insertion events |
| **Mail Monitor** | Non-mail processes making SMTP connections, mass email |
| **Domain Monitor** | Connections to paste sites, exfil domains, suspicious TLDs, beaconing |

---

## MITRE ATT&CK Coverage

Every alert maps to one or more MITRE ATT&CK techniques. Run the MITRE export to generate a Navigator heatmap:

```python
from intel.mitre_mapper import export_navigator_heatmap
export_navigator_heatmap(alert_counts, "sentinel_heatmap.json")
# Open at: https://mitre-attack.github.io/attack-navigator/
```

Tactics covered: Execution · Persistence · Privilege Escalation · Defense Evasion · Credential Access · Discovery · Lateral Movement · Collection · Command & Control · Exfiltration · Impact

---

## Architecture

```
sentinel.py                    ← Main entry point + orchestrator
├── core/
│   ├── alert_manager.py       ← Central alert store + dedup + persistence
│   └── event_bus.py           ← Pub/sub event bus (decouples engines)
├── detection/
│   ├── behavioral/
│   │   ├── dna_engine.py      ← Z-score behavioral profiling
│   │   ├── ancestry.py        ← Process chain detection + LOLBins
│   │   ├── entropy_shield.py  ← Ransomware entropy detection
│   │   ├── temporal.py        ← Time-of-day anomaly profiling
│   │   └── chain_engine.py    ← Multi-event attack chain correlation
│   ├── ml/
│   │   └── isolation_forest.py ← IsolationForest ML plugin
│   ├── sigma/
│   │   └── sigma_engine.py    ← 30+ Sigma-style detection rules
│   └── gnn/
│       └── graph_engine.py    ← GNN lateral movement detection plugin
├── response/
│   └── response_engine.py     ← Kill · Quarantine · Block · Forensics
├── deception/
│   └── honeypot_mesh.py       ← File + network honeypots
├── dlp/
│   ├── usb_monitor.py         ← USB insertion detection
│   ├── mail_monitor.py        ← SMTP/email DLP
│   └── domain_monitor.py      ← Exfil domain + beaconing detection
├── intel/
│   └── mitre_mapper.py        ← MITRE ATT&CK mapping + Navigator export
└── tests/
    └── self_test.py           ← 11-test built-in self-test suite
```

**Design principle**: Core engines load with 2 deps. ML engines are plugins — if `numpy`/`sklearn`/`networkx` aren't installed, those plugins are skipped gracefully. The system never fails to start due to missing optional deps.

---



---

## Requirements

- Python 3.9+
- Linux / macOS / Windows
- **Core**: `psutil>=5.9.0`, `watchdog>=3.0.0`
- **ML plugins** (optional): `numpy>=1.24`, `scikit-learn>=1.3`, `networkx>=3.0`
- **Active response** (IP blocking): root / administrator privileges
- **Network honeypots**: root / administrator privileges for ports < 1024

---

## Extending SentinelEDR

Adding a new detection engine is 3 steps:

1. Create `detection/myengine.py` with a class that has a `scan(event_bus)` method
2. In `scan()`, publish alerts: `event_bus.publish("alert", {"kind": "alert", "alert": Alert(...)})`
3. Register in `sentinel.py`: `self._start_engine("MyEngine", MyEngine(), interval=5)`

The plugin loader in `sentinel.py` (`_load_plugin`) will gracefully skip any engine that fails to import.

---

## License

MIT — use freely, modify freely, deploy freely.
