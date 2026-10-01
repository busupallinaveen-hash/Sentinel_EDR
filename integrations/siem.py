#!/usr/bin/env python3
"""
integrations/siem.py — SIEM & Integration Output Layer

Forwards SentinelEDR alerts to external systems:
  - Splunk HEC (HTTP Event Collector)
  - Elasticsearch
  - Generic Webhook (Teams, Slack, PagerDuty, custom)
  - MISP (threat intel platform)

Each integration loads config from sentinel.yaml.
Missing / disabled integrations are silently skipped.

Install requests: pip install requests --break-system-packages
"""

import json, logging, threading, time, queue
from datetime import datetime
from typing import Optional

log = logging.getLogger("SentinelEDR.SIEM")

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False


class SIEMRouter:
    """
    Subscribes to the event bus and routes CRITICAL/HIGH alerts
    to all enabled SIEM integrations.
    """

    def __init__(self, config: dict):
        self._config    = config
        self._queue     = queue.Queue(maxsize=500)
        self._sinks     = []
        self._running   = False
        self._setup_sinks()

    def _setup_sinks(self):
        integrations = self._config.get("integrations", {})

        if integrations.get("splunk", {}).get("enabled"):
            s = SplunkSink(integrations["splunk"])
            self._sinks.append(s)
            log.info("Splunk HEC sink enabled")

        if integrations.get("elastic", {}).get("enabled"):
            s = ElasticSink(integrations["elastic"])
            self._sinks.append(s)
            log.info("Elasticsearch sink enabled")

        if integrations.get("webhook", {}).get("enabled"):
            s = WebhookSink(integrations["webhook"])
            self._sinks.append(s)
            log.info("Webhook sink enabled")

        if integrations.get("misp", {}).get("enabled"):
            s = MISPSink(integrations["misp"])
            self._sinks.append(s)
            log.info("MISP sink enabled")

        if not self._sinks:
            log.info("No SIEM integrations enabled (configure in sentinel.yaml)")

    def handle(self, event: dict):
        """EventBus callback — receives alert events."""
        if not self._sinks:
            return
        alert = event.get("alert")
        if not alert:
            return
        d = alert.to_dict() if hasattr(alert, "to_dict") else alert
        sev = d.get("severity", "LOW")
        # Only forward HIGH+ to avoid overwhelming SIEM
        if sev in ("CRITICAL", "HIGH"):
            try:
                self._queue.put_nowait(d)
            except queue.Full:
                pass

    def run(self, event_bus):
        """Subscribe to alerts and start dispatch loop."""
        event_bus.subscribe("alert", self.handle)
        self._running = True
        log.info(f"SIEMRouter running ({len(self._sinks)} sinks)")
        while self._running:
            try:
                alert = self._queue.get(timeout=5)
                for sink in self._sinks:
                    try:
                        sink.send(alert)
                    except Exception as e:
                        log.warning(f"SIEM sink {sink.__class__.__name__} error: {e}")
            except queue.Empty:
                continue


# ── Splunk HEC ────────────────────────────────────────────────────────────────

class SplunkSink:
    def __init__(self, cfg: dict):
        self._url   = cfg.get("hec_url", "")
        self._token = cfg.get("hec_token", "")
        self._index = cfg.get("index", "sentinel-edr")
        self._verify= cfg.get("verify_ssl", True)

    def send(self, alert: dict):
        if not REQUESTS_OK or not self._url or not self._token:
            return
        payload = {
            "time":       datetime.now().timestamp(),
            "sourcetype": "sentinel_edr",
            "index":      self._index,
            "source":     alert.get("engine", "sentinel"),
            "event":      alert,
        }
        resp = requests.post(
            self._url,
            headers={"Authorization": f"Splunk {self._token}",
                     "Content-Type": "application/json"},
            json=payload,
            timeout=5,
            verify=self._verify,
        )
        if resp.status_code not in (200, 201):
            log.warning(f"Splunk HEC error: {resp.status_code} {resp.text[:100]}")


# ── Elasticsearch ─────────────────────────────────────────────────────────────

class ElasticSink:
    def __init__(self, cfg: dict):
        self._url   = cfg.get("url", "http://localhost:9200").rstrip("/")
        self._index = cfg.get("index", "sentinel-edr")
        self._user  = cfg.get("username", "")
        self._pass  = cfg.get("password", "")
        self._verify= cfg.get("verify_ssl", True)

    def send(self, alert: dict):
        if not REQUESTS_OK or not self._url:
            return
        url  = f"{self._url}/{self._index}/_doc"
        doc  = {**alert, "@timestamp": datetime.utcnow().isoformat() + "Z"}
        auth = (self._user, self._pass) if self._user else None
        resp = requests.post(
            url, json=doc, auth=auth,
            timeout=5, verify=self._verify,
        )
        if resp.status_code not in (200, 201):
            log.warning(f"Elastic error: {resp.status_code} {resp.text[:100]}")


# ── Generic Webhook (Teams, Slack, PagerDuty, custom) ────────────────────────

class WebhookSink:
    def __init__(self, cfg: dict):
        self._url     = cfg.get("url", "")
        self._headers = cfg.get("headers", {})
        self._format  = cfg.get("format", "sentinel")  # sentinel | slack | teams

    def _format_payload(self, alert: dict) -> dict:
        sev   = alert.get("severity", "INFO")
        title = alert.get("title", "SentinelEDR Alert")
        desc  = alert.get("description", "")
        risk  = alert.get("risk_score", 0)
        mitre = alert.get("mitre_tech", "")
        color = {"CRITICAL": "#FF0000", "HIGH": "#FF6600",
                 "MEDIUM": "#FFCC00", "LOW": "#0099FF"}.get(sev, "#888888")

        if self._format == "slack":
            return {
                "attachments": [{
                    "color": color,
                    "title": f"[{sev}] {title}",
                    "text":  f"{desc}\n*Risk:* {risk} | *MITRE:* {mitre}",
                    "footer": "SentinelEDR",
                    "ts": int(time.time()),
                }]
            }
        elif self._format == "teams":
            return {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": color.lstrip("#"),
                "summary": title,
                "sections": [{
                    "activityTitle": f"🚨 [{sev}] {title}",
                    "activityText":  desc,
                    "facts": [
                        {"name": "Risk Score", "value": str(risk)},
                        {"name": "MITRE",      "value": mitre or "N/A"},
                        {"name": "Engine",     "value": alert.get("engine", "")},
                        {"name": "Host",       "value": alert.get("host", "")},
                    ],
                }]
            }
        else:
            return {"sentinel_alert": alert, "timestamp": datetime.now().isoformat()}

    def send(self, alert: dict):
        if not REQUESTS_OK or not self._url:
            return
        payload = self._format_payload(alert)
        headers = {"Content-Type": "application/json", **self._headers}
        resp = requests.post(self._url, json=payload, headers=headers, timeout=5)
        if resp.status_code not in (200, 201, 204):
            log.warning(f"Webhook error: {resp.status_code} {resp.text[:100]}")


# ── MISP ──────────────────────────────────────────────────────────────────────

class MISPSink:
    """
    Pushes CRITICAL alerts to MISP as threat intelligence events.
    Only creates events for confirmed high-confidence detections.
    """

    def __init__(self, cfg: dict):
        self._url    = cfg.get("url", "").rstrip("/")
        self._key    = cfg.get("key", "")
        self._verify = cfg.get("verify_ssl", False)
        self._org_id = cfg.get("org_id", 1)

    def send(self, alert: dict):
        if not REQUESTS_OK or not self._url or not self._key:
            return
        if alert.get("severity") != "CRITICAL":
            return  # Only push CRITICAL to MISP

        mitre  = alert.get("mitre_tech", "")
        title  = alert.get("title", "SentinelEDR Alert")
        desc   = alert.get("description", "")

        event = {
            "Event": {
                "info":            f"SentinelEDR: {title}",
                "distribution":    0,   # org only
                "threat_level_id": 1,   # high
                "analysis":        1,   # ongoing
                "Attribute": [
                    {"type": "text",        "category": "Other",
                     "value": desc,         "comment": "Alert description"},
                    {"type": "text",        "category": "Other",
                     "value": mitre,        "comment": "MITRE ATT&CK technique"},
                    {"type": "text",        "category": "Other",
                     "value": alert.get("host", ""),
                     "comment": "Affected host"},
                ],
            }
        }

        # Add IOCs if present
        proc = alert.get("process", {})
        if proc.get("remote_ip"):
            event["Event"]["Attribute"].append({
                "type": "ip-dst", "category": "Network activity",
                "value": proc["remote_ip"], "comment": "Remote IP from alert",
            })

        headers = {"Authorization": self._key, "Accept": "application/json",
                   "Content-Type": "application/json"}
        try:
            resp = requests.post(
                f"{self._url}/events",
                json=event, headers=headers,
                timeout=10, verify=self._verify,
            )
            if resp.status_code not in (200, 201):
                log.warning(f"MISP error: {resp.status_code} {resp.text[:100]}")
        except Exception as e:
            log.debug(f"MISP send error: {e}")
