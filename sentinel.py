#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   SentinelEDR v1.0  —  Combined NeuralGuard + IDPS Intelligence Engine     ║
║   The best of both worlds: lightweight deployment, enterprise detection      ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Detection Layers (10 engines):                                              ║
║    1. Behavioral DNA       — Z-score anomaly per (process, user) pair       ║
║    2. Process Ancestry     — LOLBin + suspicious spawn chain detection      ║
║    3. Entropy Shield       — Shannon entropy ransomware detection            ║
║    4. Temporal Anomaly     — Time-of-day behavioral profiling               ║
║    5. Behavioral Chains    — Multi-event attack sequence correlation        ║
║    6. Sigma Rules          — 30+ curated detection signatures               ║
║    7. IsolationForest ML   — Unsupervised zero-day anomaly detection        ║
║    8. LSTM Autoencoder     — Sequence-based slow/low attack detection       ║
║    9. GNN Graph Engine     — Lateral movement & multi-hop attack paths      ║
║   10. Federated Learning   — Privacy-preserving multi-node intelligence     ║
║  Response: Kill · Suspend · Quarantine · Block IP · Isolate · Forensics    ║
║  DLP:      USB · Email · Domain · Network exfiltration monitoring           ║
║  Platform: Windows · macOS · Linux (cross-platform core)                    ║
╚══════════════════════════════════════════════════════════════════════════════╝

Usage:
  python sentinel.py                     # Full mode
  python sentinel.py --lite              # Core only (2 deps)
  python sentinel.py --dry-run           # Detect only, no response
  python sentinel.py --no-ml             # Skip ML plugins
  python sentinel.py --no-dashboard      # No web UI
  python sentinel.py --status            # Show alert summary
  python sentinel.py --test              # Self-test all engines
  python sentinel.py --simulate          # Run attack scenario simulator
  python sentinel.py --list-plugins      # Show plugin status
  python sentinel.py --export-mitre      # Export ATT&CK Navigator heatmap
"""

import os, sys, json, time, argparse, platform, logging, threading, signal
from pathlib import Path
from datetime import datetime

ROOT   = Path(__file__).parent
SYSTEM = platform.system()

# ── Bootstrap paths ───────────────────────────────────────────────────────────
import tempfile as _tempfile
import os as _os
_tmp = Path(_os.environ.get("TEMP") or _os.environ.get("TMP") or _os.environ.get("TMPDIR") or _tempfile.gettempdir())

PATHS = {
    "log":        _tmp / "sentinel_edr.log",
    "alerts":     _tmp / "sentinel_alerts.json",
    "quarantine": Path("/var/lib/sentinel/quarantine") if SYSTEM == "Linux"
                  else Path(os.environ.get("APPDATA", str(_tmp))) / "SentinelEDR" / "quarantine",
    "forensics":  Path("/var/lib/sentinel/forensics") if SYSTEM == "Linux"
                  else Path(os.environ.get("APPDATA", str(_tmp))) / "SentinelEDR" / "forensics",
    "models":     ROOT / "models",
}
for p in PATHS.values():
    p.parent.mkdir(parents=True, exist_ok=True)

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.FileHandler(str(PATHS["log"]), encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("SentinelEDR")
sys.path.insert(0, str(ROOT))

# ── Dependency check ──────────────────────────────────────────────────────────
def _check_deps(full_mode: bool):
    missing_core = []
    for pkg in ["psutil", "watchdog"]:
        try:
            __import__(pkg)
        except ImportError:
            missing_core.append(pkg)
    if missing_core:
        print(f"[!] Missing required deps: {', '.join(missing_core)}")
        print(f"    pip install {' '.join(missing_core)}")
        sys.exit(1)
    if full_mode:
        import sys as _sys
        py_ver = _sys.version_info
        if py_ver >= (3, 14):
            log.warning(
                f"Python {py_ver.major}.{py_ver.minor} detected — scikit-learn not yet "
                f"supported on Python 3.14+. ML plugins (IsolationForest, LSTM, Federated) "
                f"will be skipped. Use Python 3.11 or 3.12 for full ML support."
            )
            return
        missing_opt = []
        for pkg in ["numpy", "sklearn", "networkx"]:
            try:
                __import__("sklearn" if pkg == "sklearn" else pkg)
            except ImportError:
                missing_opt.append(pkg)
        if missing_opt:
            log.warning(f"Optional ML deps missing ({', '.join(missing_opt)}) — ML plugins disabled. "
                        f"pip install numpy scikit-learn networkx")


def banner(args):
    print(f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║              SentinelEDR v1.0  —  Unified Detection & Response             ║
╚══════════════════════════════════════════════════════════════════════════════╝
  Platform  : {SYSTEM} {platform.release()} ({platform.machine()})
  Host      : {platform.node()}
  Mode      : {"LITE (core engines only)" if args.lite else "FULL (all engines)"}
  Dry-run   : {"YES — detection only, no automated response" if args.dry_run else "NO — active response enabled"}
  Dashboard : {"Disabled" if getattr(args,"no_dashboard",False) else "http://localhost:8888"}
  Alerts    : {PATHS["alerts"]}
  Log       : {PATHS["log"]}
""")


# ── Plugin loader ─────────────────────────────────────────────────────────────
def _load_plugin(module_path: str, class_name: str, *args, **kwargs):
    try:
        parts = module_path.split(".")
        mod   = __import__(module_path, fromlist=[parts[-1]])
        cls   = getattr(mod, class_name)
        return cls(*args, **kwargs)
    except ImportError as e:
        log.debug(f"Plugin {class_name} not loaded (missing dep): {e}")
        return None
    except Exception as e:
        log.warning(f"Plugin {class_name} init error: {e}")
        return None


# ── Orchestrator ──────────────────────────────────────────────────────────────
class SentinelOrchestrator:
    def __init__(self, args):
        self.args        = args
        self.running     = False
        self._threads    = []
        self._engines    = {}
        self._start_time = time.time()

        from core.alert_manager import AlertManager
        from core.event_bus     import EventBus
        self.alert_mgr = AlertManager(str(PATHS["alerts"]))
        self.event_bus = EventBus()
        self.event_bus.subscribe("alert", self.alert_mgr.handle)

    def _start_engine(self, name: str, engine, interval: float = None):
        if engine is None:
            return
        self._engines[name] = engine
        if interval is not None:
            def _loop():
                while self.running:
                    try:
                        engine.scan(self.event_bus)
                    except Exception as e:
                        log.error(f"[{name}] scan error: {e}")
                    time.sleep(interval)
        else:
            def _loop():
                try:
                    engine.run(self.event_bus)
                except Exception as e:
                    log.error(f"[{name}] run error: {e}")
        t = threading.Thread(target=_loop, name=name, daemon=True)
        t.start()
        self._threads.append(t)
        log.info(f"✅  {name}")

    def start(self):
        self.running = True
        args = self.args

        # ── Core engines (always loaded) ──────────────────────────────────────
        log.info("Loading core detection engines...")
        from detection.behavioral.dna_engine     import BehavioralDNAEngine
        from detection.behavioral.ancestry       import ProcessAncestryEngine
        from detection.behavioral.entropy_shield import EntropyShieldEngine
        from detection.behavioral.temporal       import TemporalAnomalyEngine
        from detection.behavioral.chain_engine   import BehavioralChainEngine
        from deception.honeypot_mesh             import HoneypotMesh
        from response.response_engine            import ResponseEngine

        si = 3  # scan interval

        self._start_engine("BehavioralDNA",   BehavioralDNAEngine(),   si)
        self._start_engine("ProcessAncestry", ProcessAncestryEngine(), si)
        self._start_engine("TemporalAnomaly", TemporalAnomalyEngine(), si)
        self._start_engine("BehavioralChain", BehavioralChainEngine(), si)
        self._start_engine("EntropyShield",   EntropyShieldEngine())      # watchdog-driven
        self._start_engine("HoneypotMesh",    HoneypotMesh())             # passive listener

        # Response engine
        resp = ResponseEngine(paths=PATHS, dry_run=args.dry_run,
                              auto_respond=not args.dry_run,
                              isolate_on_ransomware=_get_config_value(
                                  "response.isolate_on_ransomware", False),
                              kill_threshold=_get_config_value(
                                  "response.kill_threshold", 85),
                              block_ip_threshold=_get_config_value(
                                  "response.block_ip_threshold", 75))
        self.event_bus.subscribe("alert", resp.handle_alert)
        self._engines["ResponseEngine"] = resp
        log.info("✅  ResponseEngine")

        # ── DLP plugins ───────────────────────────────────────────────────────
        log.info("Loading DLP monitors...")
        self._start_engine("USBMonitor",    _load_plugin("dlp.usb_monitor",    "USBMonitor"),   5)
        self._start_engine("MailMonitor",   _load_plugin("dlp.mail_monitor",   "MailMonitor"),  30)
        self._start_engine("DomainMonitor", _load_plugin("dlp.domain_monitor", "DomainMonitor"),10)

        # ── Threat intelligence ───────────────────────────────────────────────
        self._start_engine("ThreatIntel",
                           _load_plugin("intel.threat_intel", "ThreatIntelEngine"), 15)

        # ── Optional ML plugins ───────────────────────────────────────────────
        if not args.lite and not getattr(args, "no_ml", False):
            log.info("Loading ML plugins...")
            self._start_engine("SigmaEngine",
                _load_plugin("detection.sigma.sigma_engine", "SigmaEngine"), si)
            self._start_engine("IsolationForest",
                _load_plugin("detection.ml.isolation_forest", "IsolationForestEngine",
                             str(PATHS["models"])), 5)
            self._start_engine("LSTMEngine",
                _load_plugin("detection.ml.lstm_engine", "LSTMEngine",
                             str(PATHS["models"])), 8)
            self._start_engine("GNNEngine",
                _load_plugin("detection.gnn.graph_engine", "GNNEngine"), 5)

            # Federated (needs central server URL from config)
            fed_url = _get_config_value("server.central_server_url", "")
            node_id = _get_config_value("agent.node_id", platform.node())
            if fed_url:
                self._start_engine("Federated",
                    _load_plugin("detection.ml.federated_engine", "FederatedEngine",
                                 str(PATHS["models"]), fed_url, node_id), 5)

        # ── Platform sensors (optional, deep telemetry) ───────────────────────
        if not args.lite:
            if SYSTEM == "Windows":
                self._start_engine("ETWSensor",
                    _load_plugin("sensors.windows.etw_sensor", "ETWSensor"))
                    # No interval — ETWSensor is event-driven, uses run() not scan()
            elif SYSTEM == "Linux":
                self._start_engine("eBPFSensor",
                    _load_plugin("sensors.linux.ebpf_sensor", "EBPFSensor"))

        # ── SIEM integrations ─────────────────────────────────────────────────
        siem_cfg = _load_siem_config()
        if siem_cfg:
            siem = _load_plugin("integrations.siem", "SIEMRouter", siem_cfg)
            if siem:
                self.event_bus.subscribe("alert", siem.handle)
                self._engines["SIEM"] = siem
                log.info("✅  SIEMRouter")

        # ── Desktop notifications ────────────────────────────────────────────────
        if not getattr(args, "no_notify", False):
            try:
                from config.config import Config
                full_cfg = Config()._data
            except Exception:
                full_cfg = {}
            notifier = _load_plugin("integrations.notifier", "NotificationEngine", full_cfg)
            if notifier:
                self.event_bus.subscribe("alert", notifier.handle)
                self._engines["Notifier"] = notifier
                log.info("✅  NotificationEngine")

        # ── Dashboard ─────────────────────────────────────────────────────────
        if not getattr(args, "no_dashboard", False):
            try:
                from dashboard.dashboard_server import DashboardServer
                dash = DashboardServer(port=8888, orchestrator=self)
                dash.start()
                self._engines["Dashboard"] = dash
            except Exception as e:
                log.warning(f"Dashboard failed to start: {e}")

        # ── Central server reporter ───────────────────────────────────────────
        central_url = _get_config_value("server.central_server_url", "")
        if central_url:
            self._start_central_reporter(central_url,
                                         _get_config_value("agent.node_id", platform.node()))

        active = len([e for e in self._engines if e != "ResponseEngine"])
        log.info(f"\n  SentinelEDR running — {active} engines active\n")

    def _start_central_reporter(self, url: str, node_id: str):
        """Periodically POST alerts to central server."""
        import urllib.request
        last_sent = [0]
        last_count = [0]

        def _report():
            # Register with central server
            try:
                payload = json.dumps({
                    "node_id": node_id,
                    "hostname": platform.node(),
                }).encode()
                req = urllib.request.Request(
                    f"{url.rstrip('/')}/api/register",
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                urllib.request.urlopen(req, timeout=5)
                log.info(f"Registered with central server: {url}")
            except Exception as e:
                log.debug(f"Central server registration failed: {e}")

            while self.running:
                time.sleep(30)
                try:
                    # Heartbeat
                    hb = json.dumps({"node_id": node_id}).encode()
                    req = urllib.request.Request(
                        f"{url.rstrip('/')}/api/heartbeat",
                        data=hb,
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    urllib.request.urlopen(req, timeout=5)

                    # Send new alerts
                    alerts = self.alert_mgr.get_recent(500)
                    new_alerts = alerts[last_count[0]:]
                    if new_alerts:
                        payload = json.dumps({
                            "node_id": node_id,
                            "alerts": [a.to_dict() for a in new_alerts],
                        }).encode()
                        req = urllib.request.Request(
                            f"{url.rstrip('/')}/api/alerts",
                            data=payload,
                            headers={"Content-Type": "application/json"},
                            method="POST",
                        )
                        urllib.request.urlopen(req, timeout=10)
                        last_count[0] = len(alerts)
                except Exception as e:
                    log.debug(f"Central reporter error: {e}")

        t = threading.Thread(target=_report, name="CentralReporter", daemon=True)
        t.start()
        self._threads.append(t)
        log.info(f"✅  CentralReporter → {url}")

    def stop(self):
        self.running = False
        log.info("SentinelEDR shutting down...")

    def status(self):
        print(f"\n  Active Engines ({len(self._engines)}):")
        for name in sorted(self._engines):
            print(f"    ✅  {name}")
        self.alert_mgr.print_summary()


# ── Config helpers ────────────────────────────────────────────────────────────
def _get_config_value(key_path: str, default=None):
    """Read a dotted key from sentinel.yaml if it exists."""
    try:
        from config.config import Config
        cfg = Config()
        parts = key_path.split(".")
        val = cfg._data
        for p in parts:
            val = val.get(p, {})
        return val if val != {} else default
    except Exception:
        return default


def _load_siem_config() -> dict:
    try:
        from config.config import Config
        cfg = Config()
        integrations = cfg._data.get("integrations", {})
        has_any = any(
            v.get("enabled") for v in integrations.values()
            if isinstance(v, dict)
        )
        return integrations if has_any else {}
    except Exception:
        return {}


# ── Commands ──────────────────────────────────────────────────────────────────
def cmd_status():
    from core.alert_manager import AlertManager
    import tempfile, os
    # Always use OS temp dir — consistent across all commands on Windows
    alert_path = os.path.join(
        os.environ.get("TEMP") or os.environ.get("TMP") or tempfile.gettempdir(),
        "sentinel_alerts.json"
    )
    mgr = AlertManager(alert_path)
    mgr.print_summary()


def cmd_test():
    print("\n[TEST] Running SentinelEDR self-test...")
    from tests.self_test import run_all
    success = run_all()
    sys.exit(0 if success else 1)


def cmd_simulate(scenario: str = "all"):
    from tests.alert_simulator import main as sim_main
    sys.argv = ["alert_simulator.py", "--scenario", scenario]
    sim_main()


def cmd_logs(n: int = 50):
    """Show recent log entries from the log file."""
    import os, tempfile
    log_path = os.path.join(
        os.environ.get("TEMP") or os.environ.get("TMP") or tempfile.gettempdir(),
        "sentinel_edr.log"
    )
    if not os.path.exists(log_path):
        print(f"No log file found at {log_path}")
        return
    with open(log_path, encoding="utf-8", errors="replace") as f:
        lines = f.readlines()
    recent = lines[-n:]
    print(f"\n  Last {len(recent)} log entries from {log_path}:\n")
    for line in recent:
        print("  " + line.rstrip())
    print()

def cmd_clear_alerts():
    """Clear the stored alert JSON file."""
    import os, tempfile
    alert_path = os.path.join(
        os.environ.get("TEMP") or os.environ.get("TMP") or tempfile.gettempdir(),
        "sentinel_alerts.json"
    )
    if os.path.exists(alert_path):
        os.remove(alert_path)
        print(f"  Alerts cleared: {alert_path}")
    else:
        print(f"  No alert file found at {alert_path}")

def cmd_restore_network():
    """
    Manual undo for ISOLATE_HOST. Safe to run even if the host was never
    isolated (or in the wrong state) — each platform's restore only removes
    the exact rules SentinelEDR's own naming/tagging would have added.
    """
    from response.response_engine import ResponseEngine
    resp = ResponseEngine(paths=PATHS, dry_run=False, auto_respond=False)
    resp._isolated = True  # force-allow restore even if this process didn't isolate it
    resp._isolate_rules = []  # platform branches below re-derive what to remove
    import platform as _platform
    system = _platform.system()
    if system == "Windows":
        resp._isolate_rules = ["SentinelIsolate_Out", "SentinelIsolate_In"]
    elif system == "Linux":
        resp._isolate_rules = [
            ["iptables", "-I", "OUTPUT", "1", "-o", "lo", "-j", "ACCEPT"],
            ["iptables", "-I", "INPUT",  "1", "-i", "lo", "-j", "ACCEPT"],
            ["iptables", "-I", "OUTPUT", "2", "-j", "DROP"],
            ["iptables", "-I", "INPUT",  "2", "-j", "DROP"],
        ]
    elif system == "Darwin":
        resp._isolate_rules = ["anchor:sentinel_isolate"]
    result = resp._restore_network()
    print(f"\n  {result}\n")

def cmd_export_mitre():
    from intel.mitre_mapper import export_navigator_heatmap
    from core.alert_manager import AlertManager
    mgr   = AlertManager(str(PATHS["alerts"]))
    stats = mgr.get_stats()
    out   = str(_tmp / "sentinel_mitre_heatmap.json")
    export_navigator_heatmap(stats, out)
    print(f"\n  MITRE ATT&CK Navigator heatmap exported: {out}")
    print(f"  Open at: https://mitre-attack.github.io/attack-navigator/\n")


def cmd_list_plugins():
    plugins = [
        ("detection.sigma.sigma_engine",       "SigmaEngine",          "built-in"),
        ("detection.ml.isolation_forest",       "IsolationForestEngine","numpy + scikit-learn"),
        ("detection.ml.lstm_engine",            "LSTMEngine",           "numpy"),
        ("detection.gnn.graph_engine",          "GNNEngine",            "numpy + networkx"),
        ("detection.ml.federated_engine",       "FederatedEngine",      "numpy + scikit-learn"),
        ("dlp.usb_monitor",                     "USBMonitor",           "psutil"),
        ("dlp.mail_monitor",                    "MailMonitor",          "psutil"),
        ("dlp.domain_monitor",                  "DomainMonitor",        "psutil"),
        ("intel.threat_intel",                  "ThreatIntelEngine",    "built-in"),
        ("forensics.forensic_engine",           "ForensicEngine",       "psutil"),
        ("integrations.siem",                   "SIEMRouter",           "built-in"),
        ("integrations.notifier",               "NotificationEngine",   "built-in"),
        ("dashboard.dashboard_server",          "DashboardServer",      "built-in"),
        ("sensors.windows.etw_sensor",          "ETWSensor",            "Windows only"),
        ("sensors.linux.ebpf_sensor",           "EBPFSensor",           "Linux only"),
    ]
    print(f"\n  {'Plugin':<35} {'Status':<5} {'Deps'}")
    print(f"  {'─'*70}")
    for mod, cls, deps in plugins:
        kwargs = ({},) if cls in ("SIEMRouter", "NotificationEngine") else ()
        inst = _load_plugin(mod, cls, *kwargs)
        mark = "✅ " if inst else "⚠️ "
        print(f"  {mark} {cls:<33} {deps}")
    print()


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="SentinelEDR — Unified Endpoint Detection & Response"
    )
    parser.add_argument("--lite",          action="store_true", help="Core engines only")
    parser.add_argument("--dry-run",       action="store_true", help="Detect only, no response")
    parser.add_argument("--no-ml",         action="store_true", help="Skip ML/GNN plugins")
    parser.add_argument("--no-dashboard",  action="store_true", help="Disable web dashboard")
    parser.add_argument("--no-notify",     action="store_true", help="Disable desktop notifications")
    parser.add_argument("--status",        action="store_true", help="Show alert summary and exit")
    parser.add_argument("--test",          action="store_true", help="Run self-test and exit")
    parser.add_argument("--simulate",      nargs="?", const="all",
                        metavar="SCENARIO",  help="Run attack simulator (all/ransomware/lateral_movement/...)")
    parser.add_argument("--list-plugins",  action="store_true", help="List plugin status")
    parser.add_argument("--export-mitre",  action="store_true", help="Export MITRE ATT&CK heatmap")
    parser.add_argument("--config",        default="sentinel.yaml", help="Config file path")
    parser.add_argument("--logs",          action="store_true", help="Show recent log entries")
    parser.add_argument("--clear-alerts",  action="store_true", help="Clear stored alerts")
    parser.add_argument("--restore-network", action="store_true",
                        help="Undo ISOLATE_HOST — remove any SentinelEDR network-isolation rules")
    args = parser.parse_args()

    if args.status:         cmd_status();                return
    if args.test:           cmd_test();                  return
    if args.simulate is not None: cmd_simulate(args.simulate); return
    if args.list_plugins:   cmd_list_plugins();          return
    if args.export_mitre:   cmd_export_mitre();          return
    if args.logs:           cmd_logs();                  return
    if getattr(args,'clear_alerts',False): cmd_clear_alerts(); return
    if getattr(args,'restore_network',False): cmd_restore_network(); return

    banner(args)
    _check_deps(full_mode=not args.lite)

    orch = SentinelOrchestrator(args)

    def _shutdown(sig, frame):
        orch.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    orch.start()

    try:
        while True:
            time.sleep(60)
            orch.alert_mgr.print_summary(brief=True)
    except KeyboardInterrupt:
        orch.stop()


if __name__ == "__main__":
    main()
