import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "controller" / "engine"))

from decision import DecisionEngine, evaluate_dry_run, is_enforced  # noqa: E402


def make_alert(rtm_id="RTM-001", hint="alert_only", pod="victim-pod", ns="shop", ts="2026-10-18T10:00:00Z"):
    return {
        "rtm_id": rtm_id,
        "rule": f"{rtm_id} test rule",
        "priority": "Warning",
        "response_hint": hint,
        "namespace": ns,
        "pod": pod,
        "ts": ts,
    }


def test_hint_mapping():
    """Verify hint mapping: alert_only -> alert_only, isolate_network -> isolate_network, kill_pod -> kill_pod."""
    engine = DecisionEngine()
    
    # alert_only
    d1 = engine.decide(make_alert(rtm_id="RTM-001", hint="alert_only", pod="p1"), now=10.0)
    assert d1 is not None
    assert d1["action"] == "alert_only"

    # isolate_network
    d2 = engine.decide(make_alert(rtm_id="RTM-003", hint="isolate_network", pod="p2"), now=10.0)
    assert d2 is not None
    assert d2["action"] == "isolate_network"

    # kill_pod
    d3 = engine.decide(make_alert(rtm_id="RTM-005", hint="kill_pod", pod="p3"), now=10.0)
    assert d3 is not None
    assert d3["action"] == "kill_pod"


def test_escalation_three_different_rules():
    """Verify 3 or more DIFFERENT rtm_ids on one pod within 300 s escalate to kill_pod."""
    clock_time = 1000.0
    engine = DecisionEngine(clock=lambda: clock_time)

    # 1st rule: RTM-001 (alert_only)
    d1 = engine.decide(make_alert(rtm_id="RTM-001", hint="alert_only", pod="pod-esc"))
    assert d1["action"] == "alert_only"
    assert d1["rtm_ids"] == ["RTM-001"]

    # 2nd rule: RTM-002 (alert_only) 30 s later
    clock_time += 30.0
    d2 = engine.decide(make_alert(rtm_id="RTM-002", hint="alert_only", pod="pod-esc"))
    assert d2["action"] == "alert_only"
    assert d2["rtm_ids"] == ["RTM-001", "RTM-002"]

    # 3rd rule: RTM-004 (alert_only) 30 s later -> escalates to kill_pod!
    clock_time += 30.0
    d3 = engine.decide(make_alert(rtm_id="RTM-004", hint="alert_only", pod="pod-esc"))
    assert d3["action"] == "kill_pod"
    assert d3["rtm_ids"] == ["RTM-001", "RTM-002", "RTM-004"]


def test_two_rules_do_not_escalate():
    """Verify 2 rules on one pod do not escalate."""
    engine = DecisionEngine()
    d1 = engine.decide(make_alert(rtm_id="RTM-001", hint="alert_only", pod="p-two"), now=100.0)
    assert d1["action"] == "alert_only"

    d2 = engine.decide(make_alert(rtm_id="RTM-002", hint="alert_only", pod="p-two"), now=120.0)
    assert d2["action"] == "alert_only"
    assert d2["rtm_ids"] == ["RTM-001", "RTM-002"]


def test_ten_second_dedupe():
    """Verify same (pod, rtm_id) within 10 s is ignored."""
    clock_time = 2000.0
    engine = DecisionEngine(clock=lambda: clock_time)

    # First occurrence
    d1 = engine.decide(make_alert(rtm_id="RTM-001", hint="alert_only", pod="p-dedupe"))
    assert d1 is not None

    # Repeat at t+5 s -> ignored
    clock_time += 5.0
    d2 = engine.decide(make_alert(rtm_id="RTM-001", hint="alert_only", pod="p-dedupe"))
    assert d2 is None

    # Repeat at t+11 s (from first occurrence) -> processed
    clock_time += 6.0  # now t+11 from original
    d3 = engine.decide(make_alert(rtm_id="RTM-001", hint="alert_only", pod="p-dedupe"))
    assert d3 is not None


def test_dry_run_safety():
    """Verify DRY_RUN defaults and safety guards."""
    # When dry_run_env=True, always True regardless of labels
    assert evaluate_dry_run({"rtm.enforce": "true"}, dry_run_env=True) is True
    assert evaluate_dry_run({}, dry_run_env=True) is True


def test_label_guard():
    """Verify only pods with rtm.enforce=true are acted upon when DRY_RUN=False."""
    # Pod with rtm.enforce=true -> not dry-run (enforced!)
    assert evaluate_dry_run({"rtm.enforce": "true"}, dry_run_env=False) is False
    # Pod without rtm.enforce label -> stays dry-run!
    assert evaluate_dry_run({"app": "auth-service"}, dry_run_env=False) is True
    # Pod with rtm.enforce=false -> stays dry-run!
    assert evaluate_dry_run({"rtm.enforce": "false"}, dry_run_env=False) is True
    # None labels -> stays dry-run!
    assert evaluate_dry_run(None, dry_run_env=False) is True


def test_namespace_filter():
    """Verify alerts outside namespace 'shop' are ignored."""
    engine = DecisionEngine()
    assert engine.decide(make_alert(ns="kube-system")) is None
    assert engine.decide(make_alert(ns="default")) is None
    assert engine.decide(make_alert(ns="rtm-tools")) is None
    assert engine.decide(make_alert(ns="shop")) is not None


def test_missing_pod():
    """Verify alerts with missing or empty pod name are ignored."""
    engine = DecisionEngine()
    assert engine.decide(make_alert(pod=None)) is None
    assert engine.decide(make_alert(pod="")) is None


def test_never_repeat_action():
    """Verify that disruptive actions (isolate_network, kill_pod) are never repeated on the same pod."""
    engine = DecisionEngine()
    
    # 1. isolate_network taken on pod
    d1 = engine.decide(make_alert(rtm_id="RTM-003", hint="isolate_network", pod="p-rep"), now=10.0)
    assert d1["action"] == "isolate_network"

    # Another alert with isolate_network for the same pod -> suppressed
    d2 = engine.decide(make_alert(rtm_id="RTM-006", hint="isolate_network", pod="p-rep"), now=25.0)
    assert d2 is None

    # kill_pod on the same pod is allowed
    d3 = engine.decide(make_alert(rtm_id="RTM-005", hint="kill_pod", pod="p-rep"), now=30.0)
    assert d3["action"] == "kill_pod"

    # Further actions on the killed pod are suppressed
    d4 = engine.decide(make_alert(rtm_id="RTM-007", hint="kill_pod", pod="p-rep"), now=45.0)
    assert d4 is None


def test_strategy_always_delete():
    """Verify always_delete strategy deletes pod on any valid alert."""
    engine = DecisionEngine(strategy="always_delete")

    # alert_only hint -> deletes pod
    d1 = engine.decide(make_alert(rtm_id="RTM-001", hint="alert_only", pod="p-del"), now=10.0)
    assert d1 is not None
    assert d1["action"] == "kill_pod"
    assert d1["strategy"] == "always_delete"

    # Subsequent alert on same pod -> suppressed because kill_pod already taken
    d2 = engine.decide(make_alert(rtm_id="RTM-002", hint="alert_only", pod="p-del"), now=30.0)
    assert d2 is None

    # Namespace check still applies
    d3 = engine.decide(make_alert(rtm_id="RTM-001", hint="alert_only", pod="p-del2", ns="default"), now=10.0)
    assert d3 is None


def test_strategy_detect_only():
    """Verify detect_only strategy never mutates and maps to alert_only."""
    engine = DecisionEngine(strategy="detect_only")

    # kill_pod hint -> alert_only
    d1 = engine.decide(make_alert(rtm_id="RTM-007", hint="kill_pod", pod="p-det"), now=10.0)
    assert d1 is not None
    assert d1["action"] == "alert_only"
    assert d1["strategy"] == "detect_only"

    # isolate_network hint -> alert_only
    d2 = engine.decide(make_alert(rtm_id="RTM-003", hint="isolate_network", pod="p-det2"), now=10.0)
    assert d2 is not None
    assert d2["action"] == "alert_only"

    # evaluate_dry_run with detect_only stays dry even if dry_run_env=False and enforced
    assert evaluate_dry_run({"rtm.enforce": "true"}, dry_run_env=False, strategy="detect_only") is True
