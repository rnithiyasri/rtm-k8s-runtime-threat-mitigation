"""Pure decision engine for RTM response controller (Phase 2).

State is kept entirely in memory (lost on container restart).
No Kubernetes API calls or network calls are made here.
"""
from typing import Callable, Dict, List, Optional, Set, Tuple
import time


def is_enforced(pod_labels: Optional[dict], selector: str = "rtm.enforce=true") -> bool:
    """Return True if pod_labels match the enforce selector."""
    if not pod_labels:
        return False
    key, sep, val = selector.partition("=")
    expected = val if sep else "true"
    return str(pod_labels.get(key, "")).lower() == expected.lower()


def evaluate_dry_run(
    pod_labels: Optional[dict],
    dry_run_env: bool = True,
    selector: str = "rtm.enforce=true",
) -> bool:
    """Evaluate whether an action on a pod must stay dry-run."""
    if dry_run_env:
        return True
    if not is_enforced(pod_labels, selector):
        return True
    return False


class DecisionEngine:
    """Pure decision logic with in-memory state and injectable clock."""

    def __init__(
        self,
        clock: Callable[[], float] = time.time,
        window_s: float = 300.0,
        dedupe_s: float = 10.0,
    ):
        self.clock = clock
        self.window_s = window_s
        self.dedupe_s = dedupe_s
        # pod -> list of (timestamp, rtm_id)
        self._pod_history: Dict[str, List[Tuple[float, str]]] = {}
        # pod -> dict of rtm_id -> last_seen_timestamp
        self._pod_last_seen: Dict[str, Dict[str, float]] = {}
        # pod -> set of actions already taken ("isolate_network", "kill_pod")
        self._actions_taken: Dict[str, Set[str]] = {}

    def decide(self, alert: Optional[dict], now: Optional[float] = None) -> Optional[dict]:
        """Evaluate an alert and return a decision dict, or None if ignored."""
        if not alert:
            return None

        # Must be an RTM alert
        rtm_id = alert.get("rtm_id")
        if not rtm_id:
            return None

        # Must be in namespace 'shop'
        if alert.get("namespace") != "shop":
            return None

        # Pod name must be present
        pod = alert.get("pod")
        if not pod:
            return None

        t = now if now is not None else self.clock()

        # 10 s dedupe: Ignore a repeat of the same (pod, rtm_id) within 10 s
        last_seen = self._pod_last_seen.get(pod, {}).get(rtm_id)
        if last_seen is not None and (t - last_seen) < self.dedupe_s:
            return None

        # Update last seen timestamp for this (pod, rtm_id)
        if pod not in self._pod_last_seen:
            self._pod_last_seen[pod] = {}
        self._pod_last_seen[pod][rtm_id] = t

        # Append to history and prune entries outside the 300 s window
        if pod not in self._pod_history:
            self._pod_history[pod] = []
        self._pod_history[pod].append((t, rtm_id))
        self._pod_history[pod] = [
            (ts, r) for ts, r in self._pod_history[pod] if (t - ts) <= self.window_s
        ]

        # Unique RTM IDs seen on this pod within the window
        unique_rtms = sorted(list({r for _, r in self._pod_history[pod]}))

        # Check: Never repeat an action already taken on that pod
        taken = self._actions_taken.setdefault(pod, set())
        if "kill_pod" in taken:
            return None

        # Determine planned action from hint
        hint = alert.get("response_hint")
        if hint == "kill_pod":
            planned_action = "kill_pod"
            reason = "hint_kill_pod"
        elif hint == "isolate_network":
            planned_action = "isolate_network"
            reason = "hint_isolate_network"
        else:
            planned_action = "alert_only"
            reason = "hint_alert_only"

        # If isolate_network was already taken, suppress repeat isolate or alert_only actions
        if "isolate_network" in taken and planned_action != "kill_pod":
            return None

        # Escalation rule: 3 or more DIFFERENT rtm_ids on one pod within 300 s -> delete it
        if len(unique_rtms) >= 3:
            planned_action = "kill_pod"
            reason = "escalation_3_different_rules"

        if planned_action in ("isolate_network", "kill_pod"):
            if planned_action in taken:
                return None
            taken.add(planned_action)

        return {
            "pod": pod,
            "rtm_ids": unique_rtms,
            "action": planned_action,
            "reason": reason,
            "alert_ts": alert.get("ts"),
            "received_ts": t,
        }
