"""RTM stub-receiver (Phase 1.5).

Receives Falco alerts from Falcosidekick, normalizes RTM-rule alerts into one
structured JSON log line, and keeps the last 200 in memory.
NO response actions here; that is Phase 2/3.
"""
import json
import logging
import re
import threading
from collections import deque
from typing import Optional

import uvicorn
from fastapi import FastAPI, Request

MAX_ALERTS = 200
RTM_ID_RE = re.compile(r"^(RTM-\d{3})\b")

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("stub-receiver")


def parse_alert(body: dict) -> Optional[dict]:
    """Return a normalized alert dict, or None if this is not an RTM rule."""
    rule = body.get("rule") or ""
    match = RTM_ID_RE.match(rule)
    if not match:
        return None
    raw_tags = body.get("tags") or []
    if isinstance(raw_tags, str):
        raw_tags = [t.strip() for t in raw_tags.split(",")]
    tags = [t for t in raw_tags if t]
    hint = next(
        (t[len("response_"):] for t in tags if t.startswith("response_")),
        "unknown",
    )
    fields = body.get("output_fields") or {}
    return {
        "ts": body.get("time"),
        "rtm_id": match.group(1),
        "rule": rule,
        "priority": body.get("priority"),
        "tags": tags,
        "response_hint": hint,
        "namespace": fields.get("k8s.ns.name"),
        "pod": fields.get("k8s.pod.name"),
        "container_id": fields.get("container.id"),
        "user": fields.get("user.name"),
        "cmdline": fields.get("proc.cmdline"),
        "hostname": body.get("hostname") or fields.get("hostname"),
    }


class AlertStore:
    """Thread-safe ring buffer holding the most recent alerts."""

    def __init__(self, maxlen: int = MAX_ALERTS):
        self._items = deque(maxlen=maxlen)
        self._lock = threading.Lock()

    def add(self, alert: dict) -> None:
        with self._lock:
            self._items.append(alert)

    def recent(self) -> list:
        with self._lock:
            return list(self._items)

    def clear(self) -> None:
        with self._lock:
            self._items.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)


store = AlertStore()
app = FastAPI(title="stub-receiver")


@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": "stub-receiver"}


@app.post("/alerts")
async def receive_alert(request: Request):
    body = await request.json()
    alert = parse_alert(body)
    if alert is None:
        logger.info(
            "non-rtm alert ignored rule=%s priority=%s",
            body.get("rule", "unknown"),
            body.get("priority", "unknown"),
        )
        return {"received": True, "stored": False}
    store.add(alert)
    logger.info(json.dumps(alert, separators=(",", ":")))
    return {"received": True, "stored": True}


@app.get("/alerts/recent")
def alerts_recent():
    alerts = store.recent()
    return {"count": len(alerts), "alerts": alerts}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)