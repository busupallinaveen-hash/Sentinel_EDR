#!/usr/bin/env python3
"""
config/config.py — SentinelEDR Configuration System

Loads sentinel.yaml (or sentinel.json) from:
  1. Path specified by --config flag
  2. ./sentinel.yaml (current directory)
  3. /etc/sentinel_edr/sentinel.yaml (system-wide)
  4. Built-in defaults (always works with zero config)

All engine constants pull from here so nothing is hardcoded.
"""

import json, logging, os, platform
from pathlib import Path
from typing import Any, Optional

log    = logging.getLogger("SentinelEDR.Config")
SYSTEM = platform.system()

# ── Built-in defaults ─────────────────────────────────────────────────────────
DEFAULTS = {
    "agent": {
        "name":             "SentinelEDR",
        "version":          "1.0.0",
        "scan_interval":    3,       # seconds between process scans
        "extended_interval":10,      # seconds for heavier scans
        "max_alerts":       5000,
        "log_level":        "INFO",
    },
    "paths": {
        "log":        None,          # auto: /tmp or platform default
        "alerts":     None,
        "quarantine": None,
        "forensics":  None,
        "models":     "models",
    },
    "detection": {
        "behavioral_dna": {
            "enabled":        True,
            "z_threshold":    5.0,
            "min_samples":    10,
            "profile_window": 300,
        },
        "entropy_shield": {
            "enabled":           True,
            "entropy_threshold": 7.2,
            "sample_bytes":      8192,
            "velocity_window":   60,
            "velocity_limit":    20,
        },
        "temporal_anomaly": {
            "enabled":           True,
            "min_observations":  30,
            "rare_threshold":    0.02,
        },
        "sigma": {
            "enabled": True,
        },
        "behavioral_chains": {
            "enabled": True,
        },
        "isolation_forest": {
            "enabled":       True,
            "contamination": 0.05,
            "train_min":     100,
            "retrain_every": 500,
        },
        "gnn": {
            "enabled":       True,
            "window_secs":   1800,
            "score_thresh":  0.75,
        },
        "lstm": {
            "enabled":       True,
            "sequence_len":  20,
            "hidden_size":   64,
            "anomaly_thresh":0.15,
        },
    },
    "response": {
        "enabled":      True,
        "dry_run":      False,
        "auto_kill":    True,
        "auto_block_ip":True,
        "auto_quarantine": True,
        "auto_forensics":  True,
        "protected_processes": [
            "systemd","init","kernel","launchd",
            "winlogon","csrss","smss","lsass","services","explorer",
        ],
    },
    "honeypot": {
        "file_honeypots_enabled":    True,
        "network_honeypots_enabled": True,
        "ports": {
            "ssh":   2222,
            "http":  8080,
            "ftp":   2121,
            "mysql": 3307,
        },
    },
    "dlp": {
        "usb_monitor":    True,
        "mail_monitor":   True,
        "domain_monitor": True,
        "exfil_domains":  [],   # appended to built-in list
        "smtp_conn_threshold": 10,
        "beacon_conn_threshold": 50,
    },
    "dashboard": {
        "enabled": True,
        "host":    "127.0.0.1",
        "port":    8765,
    },
    "server": {
        "enabled":  False,
        "host":     "0.0.0.0",
        "port":     9000,
        "api_key":  "",         # set to enable auth
    },
    "integrations": {
        "splunk": {
            "enabled":    False,
            "hec_url":    "",
            "hec_token":  "",
        },
        "elastic": {
            "enabled":    False,
            "url":        "",
            "index":      "sentinel-edr",
        },
        "webhook": {
            "enabled":    False,
            "url":        "",
            "headers":    {},
        },
        "misp": {
            "enabled":    False,
            "url":        "",
            "key":        "",
        },
    },
    "sensors": {
        "etw":   {"enabled": True},   # Windows only
        "sysmon":{"enabled": True},   # Windows only
        "ebpf":  {"enabled": True},   # Linux only
    },
}


class Config:
    """
    Singleton configuration object.
    Access values with: cfg.get("detection.sigma.enabled")
    or: cfg["detection"]["sigma"]["enabled"]
    """
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._data = _deep_copy(DEFAULTS)
            cls._instance._loaded_from = "defaults"
        return cls._instance

    def load(self, path: Optional[str] = None) -> bool:
        """Load config from YAML or JSON file. Returns True if file found."""
        search_paths = []
        if path:
            search_paths = [Path(path)]
        else:
            search_paths = [
                Path("sentinel.yaml"),
                Path("sentinel.json"),
                Path("/etc/sentinel_edr/sentinel.yaml"),
                Path.home() / ".sentinel_edr" / "sentinel.yaml",
            ]

        for p in search_paths:
            if p.exists():
                try:
                    text = p.read_text(encoding="utf-8")
                    if p.suffix in (".yaml", ".yml"):
                        data = _load_yaml(text)
                    else:
                        data = json.loads(text)
                    _deep_merge(self._data, data)
                    self._loaded_from = str(p)
                    log.info(f"Config loaded from {p}")
                    return True
                except Exception as e:
                    log.warning(f"Config load error ({p}): {e}")

        log.info(f"No config file found — using defaults")
        return False

    def get(self, dotpath: str, default: Any = None) -> Any:
        """Get value by dot-path e.g. 'detection.sigma.enabled'"""
        parts = dotpath.split(".")
        node  = self._data
        for p in parts:
            if not isinstance(node, dict) or p not in node:
                return default
            node = node[p]
        return node

    def set(self, dotpath: str, value: Any):
        parts = dotpath.split(".")
        node  = self._data
        for p in parts[:-1]:
            node = node.setdefault(p, {})
        node[parts[-1]] = value

    def __getitem__(self, key):
        return self._data[key]

    def as_dict(self) -> dict:
        return _deep_copy(self._data)

    def summary(self):
        print(f"\n  Config loaded from: {self._loaded_from}")
        det = self._data.get("detection", {})
        print(f"  Detection engines:")
        for eng, cfg in det.items():
            enabled = cfg.get("enabled", True) if isinstance(cfg, dict) else True
            print(f"    {'✅' if enabled else '❌'} {eng}")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _deep_merge(base: dict, override: dict):
    """Merge override into base in-place (recursive)."""
    for k, v in override.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v


def _deep_copy(d):
    import copy
    return copy.deepcopy(d)


def _load_yaml(text: str) -> dict:
    """Minimal YAML loader — handles simple key: value and nested blocks."""
    try:
        import yaml
        return yaml.safe_load(text) or {}
    except ImportError:
        pass
    # Fallback: very basic YAML parser for flat/nested configs
    result = {}
    stack  = [(0, result)]
    for line in text.splitlines():
        stripped = line.rstrip()
        if not stripped or stripped.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if ":" in stripped:
            key, _, val = stripped.lstrip().partition(":")
            val = val.strip().strip('"').strip("'")
            # Pop stack to correct indent level
            while len(stack) > 1 and stack[-1][0] >= indent:
                stack.pop()
            parent = stack[-1][1]
            if val:
                # Coerce types
                if val.lower() == "true":
                    val = True
                elif val.lower() == "false":
                    val = False
                elif val.isdigit():
                    val = int(val)
                else:
                    try:
                        val = float(val)
                    except ValueError:
                        pass
                parent[key.strip()] = val
            else:
                parent[key.strip()] = {}
                stack.append((indent + 2, parent[key.strip()]))
    return result


# ── Global singleton ──────────────────────────────────────────────────────────
cfg = Config()
