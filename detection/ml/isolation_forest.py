#!/usr/bin/env python3
"""
detection/ml/isolation_forest.py — IsolationForest Anomaly Engine (Plugin)

Fast, online-ready ML anomaly detection. Trains on baseline telemetry
then flags events whose feature vector deviates significantly.

Detects zero-day attack patterns with no Sigma rule.

Requires: numpy, scikit-learn
Install:  pip install numpy scikit-learn --break-system-packages

Source: IDPS anomaly_engine.py, adapted for SentinelEDR plugin architecture.
"""

import hashlib, logging, math, os, threading, time
from collections import deque
from pathlib import Path

log = logging.getLogger("SentinelEDR.IsolationForest")

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    ML_OK = True
except ImportError:
    ML_OK = False

try:
    import psutil
    PSUTIL = True
except ImportError:
    PSUTIL = False

# Known baseline Windows/browser processes — learn from them but don't alert
WINDOWS_BASELINE = {
    'system idle process', 'system', 'registry', 'smss.exe', 'csrss.exe',
    'wininit.exe', 'services.exe', 'lsass.exe', 'lsaiso.exe', 'ngciso.exe',
    'svchost.exe', 'fontdrvhost.exe', 'dwm.exe', 'explorer.exe',
    'winlogon.exe', 'runtimebroker.exe', 'backgroundtaskhost.exe',
    'conhost.exe', 'dllhost.exe', 'taskhostw.exe', 'sihost.exe',
    'ctfmon.exe', 'searchhost.exe', 'startmenuexperiencehost.exe',
    'shellexperiencehost.exe', 'searchindexer.exe', 'searchprotocolhost.exe',
    'searchfilterhost.exe', 'audiodg.exe', 'spoolsv.exe', 'wudfhost.exe',
    'wmiprvse.exe', 'memcompression', 'securityhealthservice.exe',
    'securityhealthsystray.exe', 'nissrv.exe', 'msmpeng.exe',
    'mpdefendercoreservice.exe', 'mpcmdrun.exe', 'smartscreen.exe',
    'chrome.exe', 'msedge.exe', 'msedgewebview2.exe', 'firefox.exe',
    'brave.exe', 'ms-teams.exe', 'onedrive.exe', 'microsoftedgeupdate.exe',
    'officeclicktorun.exe', 'wmiregistrationservice.exe', 'wavessyssvc64.exe',
    'wavessvc64.exe', 'rtkaududservice64.exe', 'igfxcuiservice.exe',
    'igfxem.exe', 'intelaudioservice.exe', 'intelcphdcpsvc.exe',
    'intelcphecisvc.exe', 'esif_uf.exe', 'jhi_service.exe',
    'tbtp2pshortcutservice.exe', 'thunderboltservice.exe',
    'dellffpdwmiservice.exe', 'fwswitchservice.exe', 'hidfind.exe',
    'hidmonitorsvc.exe', 'rstmwservice.exe', 'oneapp.igcc.winservice.exe',
    'wslservice.exe', 'vmcompute.exe', 'lsaiso.exe', 'wlanext.exe',
    'moususocoreworker.exe', 'aggregatorhost.exe', 'widgetservice.exe',
    'widgetboard.exe', 'phoneexperiencehost.exe', 'crossdeviceservice.exe',
    'crossdeviceresume.exe', 'filesynchelper.exe', 'filecoauth.exe',
    'apntex.exe', 'apoint.exe', 'apremote.exe', 'apmsgfwd.exe',
    'whatsapp.root.exe', 'cowork-svc.exe', 'idps_notify.exe',
    'texttinputhost.exe', 'textinputhost.exe', 'openconsole.exe',
    'windowsterminal.exe', 'shellhost.exe', 'tabtip.exe',
    'storedesktopextension.exe', 'microsoftstartfeedprovider.exe',
    'm365copilot_autostarter.exe', 'sysmon64.exe', 'sysmon.exe',
}

FEATURE_DIM      = 8
TRAIN_MIN        = 200   # minimum samples before training (raised for better baseline)
RETRAIN_EVERY    = 1000  # retrain every N new samples (more stable baseline)
CONTAMINATION    = 0.05  # expected fraction of outliers
ANOMALY_SCORE_THRESH = -0.4  # below this = anomaly (raised from -0.2 to reduce warm-up noise)


def _extract_process_features(proc) -> "np.ndarray | None":
    """Extract 8-feature vector from a psutil process."""
    if not PSUTIL or not ML_OK:
        return None
    try:
        import numpy as np
        info = proc.as_dict(attrs=[
            "pid", "name", "cpu_percent", "memory_info",
            "num_threads", "status", "create_time"
        ])
        cpu     = info.get("cpu_percent") or 0.0
        mem_mb  = (info["memory_info"].rss / 1048576) if info.get("memory_info") else 0.0
        threads = info.get("num_threads") or 0
        age_s   = time.time() - (info.get("create_time") or time.time())
        name    = info.get("name") or ""

        conns = 0
        try:
            conns = len(proc.net_connections())
        except Exception:
            pass

        hour = (time.time() % 86400) / 3600.0  # hour of day
        name_hash = int(hashlib.md5(name.lower().encode()).hexdigest(), 16) % 1000

        vec = np.array([
            min(cpu, 100) / 100.0,
            math.log1p(mem_mb) / 10.0,
            min(threads, 100) / 100.0,
            min(conns, 50) / 50.0,
            math.log1p(age_s) / 15.0,
            math.sin(2 * math.pi * hour / 24) * 0.5 + 0.5,
            math.cos(2 * math.pi * hour / 24) * 0.5 + 0.5,
            name_hash / 1000.0,
        ], dtype=np.float32)
        return vec
    except Exception:
        return None


class IsolationForestEngine:
    ENGINE = "IsolationForest"

    def __init__(self, model_dir: str = "models"):
        if not ML_OK:
            raise ImportError("numpy + scikit-learn required for IsolationForest plugin")
        self._buffer   = deque(maxlen=2000)
        self._model    = None
        self._n_since  = 0
        self._lock     = threading.Lock()
        self._alerted  = set()
        os.makedirs(model_dir, exist_ok=True)
        self._model_path = os.path.join(model_dir, "isolation_forest.pkl")
        self._load_model()

    def _load_model(self):
        try:
            import pickle
            if os.path.exists(self._model_path):
                with open(self._model_path, "rb") as f:
                    self._model = pickle.load(f)
                log.info(f"IsolationForest model loaded from {self._model_path}")
        except Exception as e:
            log.debug(f"No saved model: {e}")

    def _save_model(self):
        try:
            import pickle
            with open(self._model_path, "wb") as f:
                pickle.dump(self._model, f)
        except Exception as e:
            log.debug(f"Model save error: {e}")

    def _train(self):
        import numpy as np
        X = np.array(list(self._buffer))
        if len(X) < TRAIN_MIN:
            return
        self._model = IsolationForest(
            contamination=CONTAMINATION,
            n_estimators=100,
            random_state=42,
            n_jobs=-1,
        )
        self._model.fit(X)
        self._save_model()
        log.info(f"IsolationForest retrained on {len(X)} samples")

    def scan(self, event_bus):
        if not PSUTIL or not ML_OK:
            return
        try:
            procs = list(psutil.process_iter())
        except Exception:
            return

        import numpy as np
        for proc in procs:
            try:
                vec = _extract_process_features(proc)
                if vec is None:
                    continue

                with self._lock:
                    self._buffer.append(vec)
                    self._n_since += 1
                    should_train = (self._n_since >= RETRAIN_EVERY
                                    and len(self._buffer) >= TRAIN_MIN)
                    if should_train:
                        self._n_since = 0

                if should_train:
                    self._train()

                if self._model is None:
                    continue

                # Skip known baseline processes — learn but don't alert
                if name.lower() in WINDOWS_BASELINE:
                    continue

                score = self._model.score_samples(vec.reshape(1, -1))[0]
                if score < ANOMALY_SCORE_THRESH:
                    info = proc.info if hasattr(proc, "info") else {}
                    pid  = proc.pid
                    name = proc.name() if callable(proc.name) else "unknown"
                    # Deduplicate: same process name within 5-min window = 1 alert
                    alert_key = f"if:{name}:{int(time.time() // 300)}"
                    with self._lock:
                        if alert_key in self._alerted:
                            continue
                        self._alerted.add(alert_key)

                    risk = min(100, int(50 + abs(score + ANOMALY_SCORE_THRESH) * 200))
                    severity = "HIGH" if risk >= 70 else "MEDIUM"

                    from core.alert_manager import Alert
                    a = Alert(
                        alert_type   = "ML_ANOMALY_ISOLATION_FOREST",
                        severity     = severity,
                        title        = f"ML anomaly: {name} (score={score:.3f})",
                        description  = (
                            f"IsolationForest flagged process '{name}' PID {pid} "
                            f"with anomaly score {score:.3f} — possible zero-day or "
                            f"novel attack pattern not matching any signature."
                        ),
                        process_info = {"pid": pid, "name": name, "if_score": round(score, 4)},
                        risk_score   = risk,
                        mitre_tactic = "defense_evasion",
                        mitre_tech   = "T1036",
                        engine       = self.ENGINE,
                    )
                    event_bus.publish("alert", {"kind": "alert", "alert": a})

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                log.debug(f"IF scan error: {e}")

        # Periodically clear alert cache
        with self._lock:
            if len(self._alerted) > 2000:
                self._alerted.clear()

    def stop(self):
        """Signal the engine to stop cleanly."""
        pass  # scan() is called externally; clean stop handled by orchestrator
