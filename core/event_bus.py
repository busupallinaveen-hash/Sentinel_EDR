#!/usr/bin/env python3
"""
core/event_bus.py — Lightweight Publish/Subscribe Event Bus

All engines publish events here. The orchestrator and response engine
subscribe to alert events. This decouples detection from response.
"""

import logging, threading
from collections import defaultdict
from typing import Callable

log = logging.getLogger("SentinelEDR.EventBus")


class EventBus:
    def __init__(self):
        self._subs: dict[str, list[Callable]] = defaultdict(list)
        self._lock = threading.Lock()

    def subscribe(self, topic: str, callback: Callable):
        with self._lock:
            self._subs[topic].append(callback)

    def publish(self, topic: str, payload: dict):
        with self._lock:
            handlers = list(self._subs.get(topic, []))
        for fn in handlers:
            try:
                fn(payload)
            except Exception as e:
                log.error(f"EventBus handler error [{topic}]: {e}")
