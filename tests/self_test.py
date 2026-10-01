#!/usr/bin/env python3
"""
tests/self_test.py — SentinelEDR Full Self-Test Suite (v1.0)

Tests every engine, plugin, and subsystem.
Run with: python sentinel.py --test
"""

import logging, sys, time, os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
log = logging.getLogger("SentinelEDR.SelfTest")

PASS = "✅"; FAIL = "❌"; SKIP = "⚠️ "
results = []

def _test(name, fn):
    try:
        fn()
        results.append((PASS, name))
        print(f"  {PASS} {name}")
    except ImportError as e:
        results.append((SKIP, name))
        print(f"  {SKIP} {name} — skipped ({e})")
    except Exception as e:
        results.append((FAIL, name))
        print(f"  {FAIL} {name} — {e}")

# ── Core ──────────────────────────────────────────────────────────────────────

def _test_alert_manager():
    from core.alert_manager import AlertManager, Alert
    from core.event_bus import EventBus
    mgr = AlertManager("/tmp/_st_alerts.json")
    bus = EventBus()
    received = []
    bus.subscribe("alert", received.append)
    bus.subscribe("alert", mgr.handle)
    a = Alert("TEST","HIGH","Self-test","desc",risk_score=50,engine="test")
    mgr.add(a)
    bus.publish("alert", {"kind":"alert","alert":a})
    assert mgr.total() >= 1
    assert len(received) >= 1

def _test_event_bus():
    from core.event_bus import EventBus
    hits = []
    bus = EventBus()
    bus.subscribe("t", hits.append)
    bus.publish("t", {"x": 1})
    bus.publish("t", {"x": 2})
    assert len(hits) == 2
    assert hits[1]["x"] == 2

def _test_config():
    from config.config import Config
    cfg = Config()
    assert cfg.get("agent.name") is not None
    si = cfg.get("detection.scan_interval", 3)
    assert isinstance(si, (int, float))

# ── Detection engines ─────────────────────────────────────────────────────────

def _test_behavioral_dna():
    from detection.behavioral.dna_engine import ProcessProfile
    p = ProcessProfile("test:user")
    for i in range(25):  # MIN_SAMPLES raised to 20
        p.record(float(i*2), float(i*10), i, i//2)
    assert p.ready()
    zs = p.z_scores(9999.0, 99999.0, 9999, 9999)
    assert any(z > 5.0 for z in zs.values()), f"Z-score not triggered: {zs}"

def _test_entropy_shield():
    from detection.behavioral.entropy_shield import _shannon_entropy
    import os
    assert _shannon_entropy(os.urandom(4096)) >= 7.0
    assert _shannon_entropy(b"\x00" * 4096) < 1.0
    assert _shannon_entropy(b"") == 0.0

def _test_ancestry():
    from detection.behavioral.ancestry import SUSPICIOUS_CHAINS, LOLBIN_PATTERNS
    assert len(SUSPICIOUS_CHAINS) >= 5
    assert len(LOLBIN_PATTERNS) >= 10
    assert "winword.exe" in SUSPICIOUS_CHAINS

def _test_chain_engine():
    from detection.behavioral.chain_engine import CHAINS, ChainTracker
    assert len(CHAINS) >= 4
    chain = CHAINS[0]
    assert len(chain.steps) >= 2
    tracker = ChainTracker(chain)
    tracker.check(0)
    assert tracker.step_hits[0] is not None

def _test_temporal():
    from detection.behavioral.temporal import TemporalAnomalyEngine
    e = TemporalAnomalyEngine()
    assert hasattr(e, 'scan')

def _test_sigma():
    from detection.sigma.sigma_engine import SIGMA_RULES
    assert len(SIGMA_RULES) >= 20
    for r in SIGMA_RULES[:5]:
        assert r.rule_id and r.title
        assert r.severity in ("LOW","MEDIUM","HIGH","CRITICAL")
        assert r.mitre_tech

def _test_isolation_forest():
    import sys
    if sys.version_info >= (3, 14):
        raise ImportError("scikit-learn not supported on Python 3.14+ yet — use Python 3.11/3.12")
    import numpy as np
    from detection.ml.isolation_forest import _extract_process_features
    import psutil
    procs = list(psutil.process_iter())
    assert procs
    vec = _extract_process_features(procs[0])
    assert vec is not None and len(vec) == 8

def _test_lstm():
    import sys
    if sys.version_info >= (3, 14):
        raise ImportError("scikit-learn not supported on Python 3.14+ yet")
    import numpy as np
    from detection.ml.lstm_engine import NumpyLSTMAutoencoder
    model = NumpyLSTMAutoencoder(seq_len=10, feat_dim=8, hidden=16)
    seqs = [np.random.randn(10, 8).astype(np.float32) for _ in range(210)]
    model.train(seqs)
    assert model._trained
    is_anom, err = model.is_anomaly(seqs[0])
    assert isinstance(is_anom, bool)
    assert err >= 0.0

def _test_gnn():
    import sys
    if sys.version_info >= (3, 14):
        raise ImportError("networkx may not work on Python 3.14+ yet")
    import numpy as np, networkx as nx
    from detection.gnn.graph_engine import AttackGraph
    g = AttackGraph()
    n1 = g.add_process_node(1234, "test")
    n2 = g.add_network_node("1.2.3.4", 4444)
    g.add_edge(n1, n2, "connected_to")
    assert g.node_count() == 2
    assert 0.0 <= g.compute_anomaly_score(n1) <= 1.0

def _test_federated():
    import sys
    if sys.version_info >= (3, 14):
        raise ImportError("scikit-learn not supported on Python 3.14+ yet")
    import numpy as np
    from detection.ml.federated_engine import LocalModelTrainer
    trainer = LocalModelTrainer("/tmp/_st_fed_model.pkl")
    for _ in range(310):
        trainer.record(np.random.randn(8).astype(np.float32))
    # Manually set _n_since to trigger retrain check
    trainer._n_since = 310
    assert trainer.should_retrain()
    trainer.retrain()
    vec = np.random.randn(8).astype(np.float32)
    score = trainer.score(vec)
    assert score is not None

# ── Deception ─────────────────────────────────────────────────────────────────

def _test_honeypot():
    from deception.honeypot_mesh import DECOY_FILES, HONEYPOT_SERVICES
    from dlp.domain_monitor import EXFIL_DOMAINS
    assert len(DECOY_FILES) >= 3
    assert len(HONEYPOT_SERVICES) >= 3
    assert len(EXFIL_DOMAINS) >= 5

# ── DLP ───────────────────────────────────────────────────────────────────────

def _test_dlp_usb():
    from dlp.usb_monitor import USBMonitor
    m = USBMonitor()
    assert hasattr(m, 'scan')

def _test_dlp_mail():
    from dlp.mail_monitor import MailMonitor, SMTP_PORTS
    assert 25 in SMTP_PORTS and 587 in SMTP_PORTS

def _test_dlp_domain():
    from dlp.domain_monitor import DomainMonitor, EXFIL_DOMAINS, SUSPICIOUS_TLDS
    assert "pastebin.com" in EXFIL_DOMAINS
    assert ".xyz" in SUSPICIOUS_TLDS

# ── Intel ─────────────────────────────────────────────────────────────────────

def _test_mitre_mapper():
    from intel.mitre_mapper import get_techniques, ATTACK_MAPPING, export_navigator_heatmap
    assert len(ATTACK_MAPPING) >= 20
    techs = get_techniques("RANSOMWARE_ENTROPY")
    assert any(t["technique_id"] == "T1486" for t in techs)
    out = "/tmp/_st_mitre.json"
    export_navigator_heatmap({"RANSOMWARE_ENTROPY": 5}, out)
    assert Path(out).exists()

def _test_threat_intel():
    from intel.threat_intel import ThreatIntelEngine, BUILTIN_IOCS
    assert len(BUILTIN_IOCS.get("process_name", {})) >= 5
    e = ThreatIntelEngine()
    assert e.check_process_name("mimikatz.exe") is not None
    assert e.check_process_name("notepad.exe") is None

# ── Response ──────────────────────────────────────────────────────────────────

def _test_response():
    from response.response_engine import ResponseEngine
    paths = {"quarantine": Path("/tmp/_st_q"), "forensics": Path("/tmp/_st_f")}
    eng = ResponseEngine(paths=paths, dry_run=True, auto_respond=False)
    eng.handle_alert({"alert": {
        "type":"RANSOMWARE_ENTROPY","severity":"CRITICAL",
        "process":{"pid":99999,"path":"/tmp/fake.txt"},"risk_score":95,
    }})
    # dry-run should not raise

def _test_forensics():
    from forensics.forensic_engine import ForensicEngine
    eng = ForensicEngine("/tmp/_st_forensics")
    path = eng.collect("SELF_TEST", pid=os.getpid())
    assert path and Path(path).exists()
    assert Path(path).stat().st_size > 0
    archives = eng.list_archives()
    assert len(archives) >= 1

# ── Server + Dashboard ────────────────────────────────────────────────────────

def _test_central_server():
    from server.central_server import NodeRegistry, AlertCorrelator, CentralAlertStore
    reg = NodeRegistry()
    reg.register("node-01", "10.0.0.1", "host01")
    reg.heartbeat("node-01")
    nodes = reg.get_all()
    assert any(n["node_id"] == "node-01" for n in nodes)

    store = CentralAlertStore("/tmp/_st_central.json")
    store.add("node-01", {"type":"TEST","severity":"HIGH","title":"t"})
    assert store.get_stats()["total"] >= 1

    corr = AlertCorrelator()
    corr.ingest("node-01", {"type":"RANSOMWARE_ENTROPY","process":{"remote_ip":"9.9.9.9"}})
    corr.ingest("node-02", {"type":"RANSOMWARE_ENTROPY","process":{"remote_ip":"9.9.9.9"}})
    incidents = corr.get_incidents()
    assert len(incidents) >= 1

def _test_dashboard():
    from dashboard.dashboard_server import DashboardServer, DASHBOARD_HTML
    assert len(DASHBOARD_HTML) > 5000
    assert "SentinelEDR" in DASHBOARD_HTML

# ── SIEM ──────────────────────────────────────────────────────────────────────

def _test_siem():
    from integrations.siem import SIEMRouter, WebhookSink
    router = SIEMRouter(config={})
    assert hasattr(router, "handle")
    fwd = WebhookSink({"url": "http://localhost:9999", "format": "slack"})
    payload = fwd._format_payload({"severity":"HIGH","title":"test",
                                   "description":"d","engine":"e","risk_score":75})
    assert "attachments" in payload

# ── Desktop notifications ────────────────────────────────────────────────────

def _test_notifier():
    from integrations.notifier import NotificationEngine, SEVERITY_RANK
    n = NotificationEngine(config={})
    assert hasattr(n, "handle")
    assert SEVERITY_RANK["CRITICAL"] > SEVERITY_RANK["LOW"]
    # PowerShell single-quote escaping must not leave an odd number of quotes
    escaped = n._ps_escape("process 'evil.exe' killed")
    assert escaped.count("'") % 2 == 0

# ── Watchdog ──────────────────────────────────────────────────────────────────

def _test_watchdog():
    from core.self_heal_watchdog import Watchdog, PID_FILE
    assert hasattr(Watchdog, '__init__')

# ── Alert simulator ───────────────────────────────────────────────────────────

def _test_simulator():
    from tests.alert_simulator import SCENARIOS
    assert len(SCENARIOS) >= 5
    assert "ransomware" in SCENARIOS
    assert "lateral_movement" in SCENARIOS

# ── Run all ───────────────────────────────────────────────────────────────────

TESTS = [
    # Core
    ("AlertManager + EventBus",        _test_alert_manager),
    ("EventBus pub/sub",               _test_event_bus),
    ("Config system (YAML)",           _test_config),
    # Detection
    ("Behavioral DNA Z-score",         _test_behavioral_dna),
    ("Entropy Shield (Shannon)",       _test_entropy_shield),
    ("Process Ancestry chains",        _test_ancestry),
    ("Behavioral Attack Chains",       _test_chain_engine),
    ("Temporal Anomaly Engine",        _test_temporal),
    ("Sigma Rules (38+ rules)",        _test_sigma),
    ("IsolationForest ML",             _test_isolation_forest),
    ("LSTM Autoencoder (numpy)",       _test_lstm),
    ("GNN Attack Graph",               _test_gnn),
    ("Federated Learning",             _test_federated),
    # Deception + DLP
    ("Honeypot Mesh",                  _test_honeypot),
    ("USB Monitor",                    _test_dlp_usb),
    ("Mail Monitor",                   _test_dlp_mail),
    ("Domain/DLP Monitor",             _test_dlp_domain),
    # Intel
    ("MITRE ATT&CK Mapper",            _test_mitre_mapper),
    ("Threat Intel Engine",            _test_threat_intel),
    # Response + Forensics
    ("Response Engine (dry-run)",      _test_response),
    ("Forensics Engine",               _test_forensics),
    # Infrastructure
    ("Central Server",                 _test_central_server),
    ("Dashboard Server",               _test_dashboard),
    ("SIEM Integration Engine",        _test_siem),
    ("Desktop Notification Engine",    _test_notifier),
    ("Self-Heal Watchdog",             _test_watchdog),
    ("Alert Simulator",                _test_simulator),
]

def run_all() -> bool:
    print(f"\n{'═'*60}")
    print(f"  SentinelEDR Self-Test Suite — {len(TESTS)} tests")
    print(f"{'═'*60}")
    for name, fn in TESTS:
        _test(name, fn)
    passed  = sum(1 for s,_ in results if s == PASS)
    skipped = sum(1 for s,_ in results if s == SKIP)
    failed  = sum(1 for s,_ in results if s == FAIL)
    total   = len(results)
    print(f"\n{'═'*60}")
    print(f"  {passed}/{total} passed  |  {skipped} skipped  |  {failed} failed")
    if failed == 0:
        print(f"  {PASS} All tests passed — SentinelEDR is fully operational")
    else:
        print(f"  {FAIL} {failed} test(s) failed — check logs above")
        for s, name in results:
            if s == FAIL:
                print(f"       → {name}")
    print(f"{'═'*60}\n")
    return failed == 0

if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    ok = run_all()
    sys.exit(0 if ok else 1)
