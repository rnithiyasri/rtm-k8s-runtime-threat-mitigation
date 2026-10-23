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
from fastapi.middleware.cors import CORSMiddleware
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
        # Decision fields — populated after decision engine runs
        "received_at": None,
        "decided_at": None,
        "dedupe_suppressed": None,
        "distinct_rule_count_in_window": None,
        "strategy": None,
        "dry_run": None,
        "action_taken": None,
        "gate_blocked_reason": None,
    }


class AlertStore:
    """Thread-safe ring buffer holding the most recent alerts."""

    def __init__(self, maxlen: int = MAX_ALERTS):
        self._items = deque(maxlen=maxlen)
        self._lock = threading.Lock()

    def add(self, alert: dict) -> None:
        with self._lock:
            self._items.append(alert)

    def update_last(self, alert_obj_id: int, fields: dict) -> None:
        """Update a record in the ring buffer by object id (reference equality)."""
        with self._lock:
            for item in self._items:
                if id(item) == alert_obj_id:
                    item.update(fields)
                    return

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

# ---------------------------------------------------------------------------
# CORS — dev/demo only. Allows the dashboard (http://localhost:5173 or
# http://localhost:8080) to poll GET endpoints from a browser.
# Restricted to GET only; no write verbs are exposed to the frontend.
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:8080",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:8080",
        "null",   # allows file:// origins (index.html opened directly in browser)
    ],
    allow_methods=["GET"],
    allow_headers=["*"],
)


@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": "rtm-controller"}


@app.get("/config")
def get_config():
    """Read-only: return current strategy/dry_run/enforce_label_selector from env.
    No write operations. Safe to expose to the dashboard."""
    return {
        "strategy": get_strategy(),
        "dry_run": DRY_RUN_ENV,
        "enforce_label_selector": ENFORCE_LABEL_SELECTOR,
    }


@app.get("/alerts/recent")
def alerts_recent():
    alerts = store.recent()
    return {"count": len(alerts), "alerts": alerts}


@app.get("/pods/status")
def pods_status(namespace: str = "shop"):
    """Read-only: return pod name, labels (rtm.enforce, rtm.tier), phase, restart count.
    Uses the existing Kubernetes Role which already grants get/list on pods in
    namespace shop. No new RBAC verbs are required."""
    if v1_api is None:
        return {"error": "kubernetes_client_unavailable", "pods": []}
    try:
        pod_list = v1_api.list_namespaced_pod(namespace=namespace)
    except Exception as e:
        return {"error": str(e), "pods": []}

    result = []
    for pod in pod_list.items:
        labels = pod.metadata.labels or {}
        containers = pod.status.container_statuses or []
        restart_count = sum(c.restart_count for c in containers)
        result.append({
            "name": pod.metadata.name,
            "namespace": pod.metadata.namespace,
            "phase": pod.status.phase,
            "labels": labels,
            "rtm_enforce": labels.get("rtm.enforce"),
            "rtm_tier": labels.get("rtm.tier"),
            "restart_count": restart_count,
        })
    return {"namespace": namespace, "pods": result}


@app.post("/alerts")
async def receive_alert(request: Request):
    received_ts = time.time()
    body = await request.json()
    alert = parse_alert(body)
    if alert is None:
        logger.info(
            "non-rtm alert ignored rule=%s priority=%s",
            body.get("rule", "unknown"),
            body.get("priority", "unknown"),
        )
        return {"received": True, "stored": False}

    # Stamp received_at before adding to store
    alert["received_at"] = received_ts

    # Store EVERY RTM alert in 200-item ring buffer before any filtering
    store.add(alert)
    alert_obj_id = id(alert)
    logger.info(json.dumps(
        {k: v for k, v in alert.items() if k not in (
            "received_at", "decided_at", "dedupe_suppressed",
            "distinct_rule_count_in_window", "strategy",
            "dry_run", "action_taken", "gate_blocked_reason"
        )},
        separators=(",", ":")
    ))

    # Sync strategy from current environment
    current_strategy = get_strategy()
    engine.strategy = current_strategy

    # Evaluate decision
    decision = engine.decide(alert)

    if decision is None:
        # Dedupe suppressed — record this on the stored alert
        store.update_last(alert_obj_id, {
            "dedupe_suppressed": True,
            "decided_at": time.time(),
            "strategy": current_strategy,
            "dry_run": DRY_RUN_ENV,
            "action_taken": "suppressed",
            "gate_blocked_reason": None,
            "distinct_rule_count_in_window": None,
        })
        return {"received": True, "stored": True, "action": None}

    pod = decision["pod"]
    action = decision["action"]
    alert_ts = decision["alert_ts"]
    received_ts_dec = decision["received_ts"]
    distinct_count = len(decision.get("rtm_ids", []))

    # Determine safety / dry_run
    pod_labels = {}
    gate_blocked_reason = None
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

    # Compute gate_blocked_reason for dashboard display
    if str(pod_labels.get("rtm.enforce", "")).lower() != "true":
        gate_blocked_reason = f"pod_missing_label:{ENFORCE_LABEL_SELECTOR}"
    elif current_strategy == "detect_only":
        gate_blocked_reason = "strategy_detect_only"
    elif DRY_RUN_ENV:
        gate_blocked_reason = "dry_run_env=true"

    if is_dry:
        logger.info("STRATEGY=%s WOULD %s pod %s", current_strategy, action, pod)
    else:
        gate_blocked_reason = None  # enforcement is live — no block
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

    decided_at = time.time()

    # Update the stored alert record with full decision metadata
    store.update_last(alert_obj_id, {
        "decided_at": decided_at,
        "dedupe_suppressed": False,
        "distinct_rule_count_in_window": distinct_count,
        "strategy": current_strategy,
        "dry_run": is_dry,
        "action_taken": action,
        "gate_blocked_reason": gate_blocked_reason,
    })

    # One JSON log line per decision, including strategy
    decision_record = {
        "strategy": current_strategy,
        "pod": pod,
        "rtm_ids": decision["rtm_ids"],
        "action": action,
        "dry_run": is_dry,
        "gate_blocked_reason": gate_blocked_reason,
        "alert_ts": alert_ts,
        "received_ts": received_ts_dec,
        "action_done_ts": decided_at,
        "distinct_rule_count_in_window": distinct_count,
    }
    logger.info(json.dumps(decision_record, separators=(",", ":")))

    return {"received": True, "stored": True, "decision": decision_record}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
