"""RTM response controller (Phase 2).

Receives Falco alerts from Falcosidekick, normalizes RTM alerts,
stores them in a 200-item ring buffer, evaluates response decisions,
and executes graduated responses (isolate_network, kill_pod) with safety guards.
"""
import json
import logging
import os
import re
import threading
import time
from collections import deque
from typing import Optional

import uvicorn
from fastapi import FastAPI, Request
from kubernetes import client, config

from decision import DecisionEngine, evaluate_dry_run

MAX_ALERTS = 200
RTM_ID_RE = re.compile(r"^(RTM-\d{3})\b")

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("rtm-controller")

# Configuration from environment
DRY_RUN_ENV = os.getenv("DRY_RUN", "true").lower() in ("true", "1", "yes")
ENFORCE_LABEL_SELECTOR = os.getenv("ENFORCE_LABEL_SELECTOR", "rtm.enforce=true")


def get_strategy() -> str:
    return os.getenv("STRATEGY", "graduated").lower()


# Initialize Kubernetes API client (fail gracefully in test/mock environments)
v1_api: Optional[client.CoreV1Api] = None
try:
    try:
        config.load_incluster_config()
    except Exception:
        config.load_kube_config()
    v1_api = client.CoreV1Api()
    logger.info("Kubernetes API client initialized successfully")
except Exception as e:
    logger.warning("Could not initialize Kubernetes client: %s (running in dry-run mode)", e)


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
engine = DecisionEngine(strategy=get_strategy())
app = FastAPI(title="rtm-controller")


@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": "rtm-controller"}


@app.get("/alerts/recent")
def alerts_recent():
    alerts = store.recent()
    return {"count": len(alerts), "alerts": alerts}


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

    # Store EVERY RTM alert in 200-item ring buffer before any filtering
    store.add(alert)
    logger.info(json.dumps(alert, separators=(",", ":")))

    # Sync strategy from current environment
    current_strategy = get_strategy()
    engine.strategy = current_strategy

    # Evaluate decision
    decision = engine.decide(alert)
    if decision is None:
        return {"received": True, "stored": True, "action": None}

    pod = decision["pod"]
    action = decision["action"]
    alert_ts = decision["alert_ts"]
    received_ts = decision["received_ts"]

    # Determine safety / dry_run
    pod_labels = {}
    if v1_api is not None:
        try:
            pod_obj = v1_api.read_namespaced_pod(name=pod, namespace="shop")
            pod_labels = pod_obj.metadata.labels or {}
        except Exception as e:
            logger.warning("Could not read pod %s in shop: %s", pod, e)

    is_dry = evaluate_dry_run(
        pod_labels=pod_labels,
        dry_run_env=DRY_RUN_ENV,
        selector=ENFORCE_LABEL_SELECTOR,
        strategy=current_strategy,
    )

    if is_dry:
        logger.info("STRATEGY=%s WOULD %s pod %s", current_strategy, action, pod)
    else:
        logger.info("STRATEGY=%s ACTION %s pod %s", current_strategy, action, pod)
        if current_strategy != "detect_only" and v1_api is not None:
            if action == "isolate_network":
                try:
                    v1_api.patch_namespaced_pod(
                        name=pod,
                        namespace="shop",
                        body={"metadata": {"labels": {"rtm.tier": "restrict"}}},
                    )
                except Exception as e:
                    logger.error("Failed to patch pod %s: %s", pod, e)
            elif action == "kill_pod":
                try:
                    v1_api.delete_namespaced_pod(name=pod, namespace="shop")
                except Exception as e:
                    logger.error("Failed to delete pod %s: %s", pod, e)

    action_done_ts = time.time()

    # One JSON log line per decision, including strategy
    decision_record = {
        "strategy": current_strategy,
        "pod": pod,
        "rtm_ids": decision["rtm_ids"],
        "action": action,
        "dry_run": is_dry,
        "alert_ts": alert_ts,
        "received_ts": received_ts,
        "action_done_ts": action_done_ts,
    }
    logger.info(json.dumps(decision_record, separators=(",", ":")))

    return {"received": True, "stored": True, "decision": decision_record}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
