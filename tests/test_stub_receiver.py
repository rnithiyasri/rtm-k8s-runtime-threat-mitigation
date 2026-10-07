import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "controller" / "stub-receiver"))

from main import MAX_ALERTS, AlertStore, parse_alert  # noqa: E402

SAMPLE = {
    "hostname": "rtm-k8s-cluster-worker",
    "priority": "Warning",
    "rule": "RTM-002 Sensitive file read in shop container",
    "tags": ["T1555", "credential_access", "response_alert_only", "rtm"],
    "time": "2026-10-07T09:42:46.671825228Z",
    "output_fields": {
        "k8s.ns.name": "shop",
        "k8s.pod.name": "order-service-abc",
        "container.id": "2f664e825796",
        "user.name": "<NA>",
        "proc.cmdline": "cat /etc/shadow",
    },
}


def test_parse_rtm_alert():
    a = parse_alert(SAMPLE)
    assert a["rtm_id"] == "RTM-002"
    assert a["priority"] == "Warning"
    assert a["response_hint"] == "alert_only"
    assert a["namespace"] == "shop"
    assert a["pod"] == "order-service-abc"
    assert a["container_id"] == "2f664e825796"
    assert a["cmdline"] == "cat /etc/shadow"
    assert a["hostname"] == "rtm-k8s-cluster-worker"


def test_non_rtm_alert_is_ignored():
    assert parse_alert({"rule": "Read sensitive file untrusted", "priority": "Warning"}) is None


def test_missing_fields_do_not_crash():
    a = parse_alert({"rule": "RTM-001 Shell spawned in shop container"})
    assert a["rtm_id"] == "RTM-001"
    assert a["response_hint"] == "unknown"
    assert a["namespace"] is None
    assert a["tags"] == []


def test_response_hint_kill_pod():
    a = parse_alert({"rule": "RTM-005 x", "tags": ["rtm", "response_kill_pod"]})
    assert a["response_hint"] == "kill_pod"


def test_ring_buffer_keeps_last_200():
    store = AlertStore()
    for i in range(MAX_ALERTS + 50):
        store.add({"n": i})
    items = store.recent()
    assert len(items) == MAX_ALERTS
    assert items[0]["n"] == 50
    assert items[-1]["n"] == MAX_ALERTS + 49


def test_empty_store():
    assert AlertStore().recent() == []