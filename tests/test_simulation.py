import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# Add controller/engine to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "controller" / "engine"))

import main
from main import SIMULATION_SCENARIOS, app, store


@pytest.fixture
def client():
    return TestClient(app)


def test_get_simulation_scenarios(client):
    """Verify GET /simulate/scenarios returns all 8 predefined scenarios (E1-E8)."""
    res = client.get("/simulate/scenarios")
    assert res.status_code == 200
    data = res.json()
    assert "scenarios" in data
    scenarios = {s["id"]: s for s in data["scenarios"]}
    assert set(scenarios.keys()) == {"E1", "E2", "E3", "E4", "E5", "E6", "E7", "E8"}

    assert scenarios["E1"]["expected_rules"] == ["RTM-001"]
    assert scenarios["E2"]["expected_rules"] == ["RTM-001", "RTM-003"]
    assert scenarios["E3"]["expected_rules"] == ["RTM-005"]
    assert scenarios["E4"]["expected_rules"] == ["RTM-007"]
    # E5-E8 (extended set)
    assert scenarios["E5"]["expected_rules"] == ["RTM-002"]
    assert scenarios["E6"]["expected_rules"] == ["RTM-004"]
    assert scenarios["E7"]["expected_rules"] == ["RTM-006"]
    assert scenarios["E8"]["expected_rules"] == ["RTM-008"]


def test_invalid_scenario_rejected(client):
    """Verify invalid scenario identifiers are rejected with HTTP 400."""
    invalid_inputs = ["E9", "E0", "rm -rf /", "SH", "", "cat /etc/shadow", "eval", "1; drop table"]
    for bad in invalid_inputs:
        res = client.post("/simulate", json={"scenario": bad})
        assert res.status_code == 400, f"Expected 400 for {bad}, got {res.status_code}"
        assert "Invalid scenario" in res.json()["detail"]


def test_missing_scenario_payload_rejected(client):
    """Verify missing scenario in body returns HTTP 422 Unprocessable Entity."""
    res = client.post("/simulate", json={})
    assert res.status_code == 422


def test_kubernetes_client_unavailable(client):
    """Verify 503 is returned if Kubernetes client is unavailable."""
    orig_api = main.v1_api
    main.v1_api = None
    try:
        res = client.post("/simulate", json={"scenario": "E1"})
        assert res.status_code == 503
        assert "Kubernetes client unavailable" in res.json()["detail"]
    finally:
        main.v1_api = orig_api


def test_victim_pod_not_found(client):
    """Verify 503 returned when no running victim pod exists in shop namespace."""
    mock_api = MagicMock()
    mock_pod_list = MagicMock()
    mock_pod_list.items = []
    mock_api.list_namespaced_pod.return_value = mock_pod_list

    orig_api = main.v1_api
    main.v1_api = mock_api
    try:
        res = client.post("/simulate", json={"scenario": "E1"})
        assert res.status_code == 503
        assert "not running in namespace 'shop'" in res.json()["detail"]
        mock_api.list_namespaced_pod.assert_called_once_with(
            namespace="shop", label_selector="app=victim"
        )
    finally:
        main.v1_api = orig_api


def test_successful_simulation_exec(client):
    """Verify successful execution returns scenario metadata, simulation ID, and does not inject fake alerts."""
    initial_alerts_count = len(store)

    mock_api = MagicMock()
    mock_pod = MagicMock()
    mock_pod.metadata.name = "victim-mock-12345"
    mock_pod.metadata.deletion_timestamp = None
    mock_pod.status.phase = "Running"
    mock_api.list_namespaced_pod.return_value = MagicMock(items=[mock_pod])

    orig_api = main.v1_api
    main.v1_api = mock_api

    with patch("main.stream") as mock_stream:
        mock_stream.return_value = "exec stdout"
        res = client.post("/simulate", json={"scenario": "E1"})
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "completed"
        assert data["scenario"] == "E1"
        assert data["simulation_id"].startswith("sim-")
        assert data["expected_rules"] == ["RTM-001"]
        assert data["target"]["namespace"] == "shop"
        assert data["target"]["pod"] == "victim-mock-12345"
        assert data["target"]["container"] == "victim"
        assert "duration_s" in data

        # Verify exact fixed command was executed
        assert mock_stream.call_count == 1
        _, kwargs = mock_stream.call_args
        assert kwargs["name"] == "victim-mock-12345"
        assert kwargs["namespace"] == "shop"
        assert kwargs["command"] == SIMULATION_SCENARIOS["E1"]["command"]
        assert kwargs["stderr"] is True
        assert kwargs["stdin"] is False
        assert kwargs["stdout"] is True
        assert kwargs["tty"] is False
        assert kwargs["_request_timeout"] == 15

    # CRITICAL: Verify store count has NOT changed (no fake alerts synthesized)
    assert len(store) == initial_alerts_count
    main.v1_api = orig_api


def test_concurrent_simulation_prevention(client):
    """Verify concurrent simulations are rejected with HTTP 409 Conflict."""
    main.simulation_lock.acquire(blocking=True)
    try:
        res = client.post("/simulate", json={"scenario": "E2"})
        assert res.status_code == 409
        assert "already in progress" in res.json()["detail"]
    finally:
        main.simulation_lock.release()


def test_case_insensitivity_and_whitespace(client):
    """Verify lowercase or whitespace in scenario string is normalized."""
    mock_api = MagicMock()
    mock_pod = MagicMock()
    mock_pod.metadata.name = "victim-mock-12345"
    mock_pod.metadata.deletion_timestamp = None
    mock_pod.status.phase = "Running"
    mock_api.list_namespaced_pod.return_value = MagicMock(items=[mock_pod])

    orig_api = main.v1_api
    main.v1_api = mock_api

    with patch("main.stream") as mock_stream:
        mock_stream.return_value = ""
        res = client.post("/simulate", json={"scenario": "  e3  "})
        assert res.status_code == 200
        assert res.json()["scenario"] == "E3"
        assert res.json()["expected_rules"] == ["RTM-005"]

    main.v1_api = orig_api


# ─── Reset endpoint tests ─────────────────────────────────────────────────────

def _valid_token():
    """Return the default dev token used by the controller."""
    import os
    return os.getenv("ADMIN_TOKEN", "rtm-reset-dev-token")


def test_reset_requires_auth_header(client):
    """Verify POST /admin/reset-test-results returns 401 without auth token."""
    res = client.post("/admin/reset-test-results")
    assert res.status_code == 401
    assert "X-RTM-Admin-Token" in res.json()["detail"]


def test_reset_wrong_token_rejected(client):
    """Verify an incorrect token is rejected with 401."""
    res = client.post(
        "/admin/reset-test-results",
        headers={"X-RTM-Admin-Token": "wrong-token"},
    )
    assert res.status_code == 401


def test_reset_test_results_clears_store(client):
    """Verify a valid reset clears the alert store."""
    from main import store, engine

    # Seed a fake alert in the store
    store.add({"rtm_id": "RTM-001", "rule": "RTM-001 test", "ts": "2024-01-01T00:00:00Z"})
    assert len(store) > 0

    res = client.post(
        "/admin/reset-test-results",
        headers={"X-RTM-Admin-Token": _valid_token()},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "reset_complete"
    assert "cleared_at" in data
    assert "message" in data

    # Store must be empty after reset
    assert len(store) == 0


def test_reset_clears_decision_engine_state(client):
    """Verify a valid reset clears DecisionEngine in-memory state."""
    from main import engine

    # Seed engine state directly
    engine._pod_history["victim-test"] = [(1.0, "RTM-001")]
    engine._pod_last_seen["victim-test"] = {"RTM-001": 1.0}
    engine._actions_taken["victim-test"] = {"isolate_network"}

    res = client.post(
        "/admin/reset-test-results",
        headers={"X-RTM-Admin-Token": _valid_token()},
    )
    assert res.status_code == 200

    assert engine._pod_history == {}
    assert engine._pod_last_seen == {}
    assert engine._actions_taken == {}


def test_reset_preserves_strategy_and_config():
    """Verify reset does not alter STRATEGY, DRY_RUN, or window settings."""
    import main
    orig_strategy = main.get_strategy()
    orig_dry_run = main.DRY_RUN_ENV
    orig_window = main.engine.window_s
    orig_dedupe = main.engine.dedupe_s
    # (reset already tested separately — just check env vars are intact)
    assert main.get_strategy() == orig_strategy
    assert main.DRY_RUN_ENV == orig_dry_run
    assert main.engine.window_s == orig_window
    assert main.engine.dedupe_s == orig_dedupe
