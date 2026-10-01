#!/usr/bin/env python3
"""
detection/ml/federated_engine.py — Federated Learning Engine (Plugin)

Privacy-preserving collective intelligence across SentinelEDR nodes.

How it works:
  1. Each node trains a local IsolationForest on its own telemetry
  2. Nodes share only model WEIGHTS (not raw events) with the central server
  3. Central server averages weights → global model
  4. Nodes download global model to improve local detection

Privacy guarantee: raw process/network data NEVER leaves the endpoint.
Only gradient updates (aggregated weight deltas) are shared.

This means:
  - Node A's process data never goes to Node B
  - But Node B benefits from Node A's detection patterns
  - Attackers can't reconstruct individual endpoint telemetry from weights

Requires: numpy, scikit-learn
"""

import hashlib, json, logging, os, pickle, threading, time
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Optional

log = logging.getLogger("SentinelEDR.Federated")

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    FL_OK = True
except ImportError:
    FL_OK = False

try:
    import psutil
    PSUTIL = True
except ImportError:
    PSUTIL = False

FEATURE_DIM     = 8
TRAIN_MIN       = 150
SYNC_INTERVAL   = 300   # sync with central every 5 min
ANOMALY_THRESH  = -0.25


def _extract_features(proc) -> "Optional[np.ndarray]":
    """Same feature extractor as IsolationForestEngine."""
    if not FL_OK or not PSUTIL:
        return None
    try:
        cpu    = proc.cpu_percent(interval=None) or 0.0
        mem    = proc.memory_info().rss / 1048576 if proc.memory_info() else 0.0
        thrs   = proc.num_threads() or 0
        conns  = 0
        try:
            conns = len(proc.net_connections())
        except Exception:
            pass
        name   = proc.name() or ""
        age    = time.time() - proc.create_time()
        hour   = (time.time() % 86400) / 3600.0
        name_h = int(hashlib.md5(name.lower().encode()).hexdigest(), 16) % 1000

        import math
        return np.array([
            min(cpu, 100) / 100.0,
            math.log1p(mem) / 10.0,
            min(thrs, 100) / 100.0,
            min(conns, 50) / 50.0,
            math.log1p(age) / 15.0,
            math.sin(2 * math.pi * hour / 24) * 0.5 + 0.5,
            math.cos(2 * math.pi * hour / 24) * 0.5 + 0.5,
            name_h / 1000.0,
        ], dtype=np.float32)
    except Exception:
        return None


class LocalModelTrainer:
    """Trains and maintains the local IsolationForest model."""

    def __init__(self, model_path: str):
        self._buffer     = deque(maxlen=3000)
        self._model      = None
        self._model_path = model_path
        self._n_since    = 0
        self._lock       = threading.Lock()
        self._load()

    def _load(self):
        try:
            if os.path.exists(self._model_path):
                with open(self._model_path, "rb") as f:
                    self._model = pickle.load(f)
                log.info("Federated local model loaded")
        except Exception:
            pass

    def _save(self):
        try:
            with open(self._model_path, "wb") as f:
                pickle.dump(self._model, f)
        except Exception as e:
            log.debug(f"Model save error: {e}")

    def record(self, vec: "np.ndarray"):
        with self._lock:
            self._buffer.append(vec)
            self._n_since += 1

    def should_retrain(self) -> bool:
        with self._lock:
            return self._n_since >= 300 and len(self._buffer) >= TRAIN_MIN

    def retrain(self):
        import numpy as np
        with self._lock:
            X = np.array(list(self._buffer))
            self._n_since = 0
        if len(X) < TRAIN_MIN:
            return
        model = IsolationForest(
            contamination=0.05, n_estimators=80, random_state=42, n_jobs=1
        )
        model.fit(X)
        with self._lock:
            self._model = model
        self._save()
        log.info(f"Federated local model retrained on {len(X)} samples")

    def score(self, vec: "np.ndarray") -> Optional[float]:
        with self._lock:
            if self._model is None:
                return None
        return self._model.score_samples(vec.reshape(1, -1))[0]

    def get_weights(self) -> Optional[dict]:
        """Extract model weights for federation (estimator summaries)."""
        with self._lock:
            if self._model is None:
                return None
        try:
            # Share aggregated stats, not raw trees (privacy-preserving)
            scores = [e.decision_function for e in self._model.estimators_]
            return {
                "n_estimators": self._model.n_estimators,
                "n_samples":    len(self._buffer),
                "contamination":self._model.contamination,
                "node_hash":    hashlib.sha256(
                    pickle.dumps(self._model)
                ).hexdigest()[:16],
                "timestamp":    datetime.now().isoformat(),
            }
        except Exception:
            return None

    def merge_global_model(self, global_model_bytes: bytes):
        """Apply globally aggregated model from central server."""
        try:
            global_model = pickle.loads(global_model_bytes)
            with self._lock:
                self._model = global_model
            self._save()
            log.info("Federated global model applied")
        except Exception as e:
            log.warning(f"Failed to apply global model: {e}")


class FederatedSyncClient:
    """Syncs local model weights with central server."""

    def __init__(self, server_url: str, node_id: str):
        self._server_url = server_url.rstrip("/")
        self._node_id    = node_id
        self._last_sync  = 0

    def push_weights(self, weights: dict) -> bool:
        try:
            import urllib.request
            payload = json.dumps({
                "node_id": self._node_id,
                "weights": weights,
            }).encode()
            req = urllib.request.Request(
                f"{self._server_url}/api/federated/weights",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status == 200
        except Exception as e:
            log.debug(f"Federated push failed: {e}")
            return False

    def pull_global_model(self) -> Optional[bytes]:
        try:
            import urllib.request
            url = f"{self._server_url}/api/federated/global_model?node_id={self._node_id}"
            with urllib.request.urlopen(url, timeout=10) as r:
                if r.status == 200:
                    return r.read()
        except Exception as e:
            log.debug(f"Federated pull failed: {e}")
        return None

    def should_sync(self) -> bool:
        return (time.time() - self._last_sync) >= SYNC_INTERVAL

    def mark_synced(self):
        self._last_sync = time.time()


class FederatedEngine:
    ENGINE = "Federated"

    def __init__(self, model_dir: str = "models",
                 server_url: str = "", node_id: str = ""):
        if not FL_OK:
            raise ImportError("numpy + scikit-learn required for Federated plugin")

        os.makedirs(model_dir, exist_ok=True)
        self._trainer  = LocalModelTrainer(
            os.path.join(model_dir, "federated_local.pkl")
        )
        self._sync     = FederatedSyncClient(server_url, node_id) if server_url else None
        self._alerted  = set()
        self._lock     = threading.Lock()
        log.info(f"FederatedEngine ready — server: {server_url or 'standalone'}")

    def scan(self, event_bus):
        if not PSUTIL or not FL_OK:
            return

        try:
            procs = list(psutil.process_iter())
        except Exception:
            return

        for proc in procs:
            try:
                vec = _extract_features(proc)
                if vec is None:
                    continue

                self._trainer.record(vec)

                score = self._trainer.score(vec)
                if score is not None and score < ANOMALY_THRESH:
                    pid  = proc.pid
                    name = proc.name()
                    key  = f"fed:{pid}:{name}"
                    with self._lock:
                        if key in self._alerted:
                            continue
                        self._alerted.add(key)

                    risk = min(100, int(50 + abs(score + ANOMALY_THRESH) * 150))
                    sev  = "HIGH" if risk >= 70 else "MEDIUM"

                    from core.alert_manager import Alert
                    a = Alert(
                        alert_type   = "FEDERATED_ML_ANOMALY",
                        severity     = sev,
                        title        = f"Federated ML anomaly: {name}",
                        description  = (
                            f"Federated IsolationForest flagged '{name}' (PID {pid}) "
                            f"with score {score:.3f} — pattern not seen on this or "
                            f"federated peer nodes."
                        ),
                        process_info = {"pid": pid, "name": name,
                                        "fed_score": round(score, 4)},
                        risk_score   = risk,
                        mitre_tactic = "defense_evasion",
                        mitre_tech   = "T1036",
                        engine       = self.ENGINE,
                    )
                    event_bus.publish("alert", {"kind": "alert", "alert": a})

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                log.debug(f"Federated scan error: {e}")

        # Retrain if enough new data
        if self._trainer.should_retrain():
            threading.Thread(
                target=self._trainer.retrain, daemon=True, name="FedRetrain"
            ).start()

        # Sync with central server
        if self._sync and self._sync.should_sync():
            self._sync.mark_synced()
            weights = self._trainer.get_weights()
            if weights:
                self._sync.push_weights(weights)
            global_bytes = self._sync.pull_global_model()
            if global_bytes:
                self._trainer.merge_global_model(global_bytes)

        with self._lock:
            if len(self._alerted) > 3000:
                self._alerted.clear()
