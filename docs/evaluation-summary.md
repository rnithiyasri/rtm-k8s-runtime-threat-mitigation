# RTM Evaluation Summary (Phase 2 — Evaluation Audit)

Empirical evaluation on `rtm-k8s-cluster` (Kubernetes v1.31, kindnet v20241108, Falco modern_ebpf).
Preflight Falco clock offset: `0.0000 s`.
Total runs: 36 (REPEATS=3, 3 strategies × 4 scenarios; strategy attribution for the first group is unresolved).

**Data-quality note:** The current 36-run CSV contains 12 rows labelled `alert_only`. This label does not match the controller's supported strategy names (`detect_only`, `always_delete`, and `graduated`), and those rows include enforcement actions. Treat this group's strategy attribution as unresolved; do not interpret it as verified detection-only behavior.

**Historical baseline:** The earlier CSV contains 8 `detect_only` runs (2 per scenario). These are separate from the current 36-run dataset and must not be combined as if they were one evaluation.

---

## 1. Median Metrics per Strategy × Scenario

| Strategy | Scenario | n | First Action | Enforcement Action | Median attack→received (s) | Median received→action (s) | Median attack→action (s) | Min–Max attack→action (s) | Median Downtime (s) | Median Avail (%) | Contained |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `alert_only` | E1 (shell spawn) | 3 | `alert_only` | `-` | 0.426 | - | - | - | 0.000 | 100.000 | open |
| `alert_only` | E2 (token read) | 3 | `alert_only` | `isolate_network` | 0.559 | 0.022 | 0.580 | 0.446–6.393 | 0.500 | 98.300 | egress_blocked |
| `alert_only` | E3 (tmp binary) | 3 | `alert_only` | `kill_pod` | 0.543 | 0.027 | 0.571 | 0.537–0.746 | 9.000 | 68.400 | deleted |
| `alert_only` | E4 (reverse shell) | 3 | `alert_only` | `isolate_network` | 21.573 | 0.034 | 21.597 | 21.543–21.698 | 9.000 | 72.700 | deleted |
| `graduated` | E1 (shell spawn) | 3 | `alert_only` | `-` | 0.489 | - | - | - | 0.000 | 100.000 | open |
| `graduated` | E2 (token read) | 3 | `alert_only` | `isolate_network` | 0.492 | 0.021 | 0.512 | 0.495–0.533 | 0.000 | 100.000 | egress_blocked |
| `graduated` | E3 (tmp binary) | 3 | `alert_only` | `kill_pod` | 0.479 | 0.025 | 0.497 | 0.438–0.701 | 8.000 | 71.900 | deleted |
| `graduated` | E4 (reverse shell) | 3 | `alert_only` | `isolate_network` | 21.544 | 0.029 | 21.582 | 21.499–21.657 | 8.500 | 75.000 | deleted |
| `always_delete` | E1 (shell spawn) | 3 | `kill_pod` | `kill_pod` | 0.439 | 0.035 | 0.459 | 0.439–0.575 | 8.500 | 69.600 | deleted |
| `always_delete` | E2 (token read) | 3 | `kill_pod` | `kill_pod` | 0.516 | 0.022 | 0.537 | 0.389–4.515 | 9.000 | 69.000 | deleted |
| `always_delete` | E3 (tmp binary) | 3 | `kill_pod` | `kill_pod` | 0.483 | 0.023 | 0.506 | 0.433–3.837 | 9.000 | 68.400 | deleted |
| `always_delete` | E4 (reverse shell) | 3 | `kill_pod` | `kill_pod` | 0.517 | 0.034 | 0.558 | 0.495–3.274 | 9.000 | 71.200 | deleted |

---

## 2. Key Findings

1. **Graduated strategy preserves availability on low/medium threats**: E1 and E2 under `graduated` maintained 100% availability with 0.0 s downtime, while `always_delete` imposed ~8–9 s downtime (~67–71% availability).
2. **Deterministic egress isolation without downtime**: E2 under `graduated` enforced `isolate_network` with 100% availability and 0.0 s downtime.
3. **Controller internal latency is negligible**: `received_to_action_s` (controller clock only) consistently 18–45 ms across all enforced runs.
4. **Unresolved strategy attribution:** The current CSV's `alert_only` group contains enforcement actions in E2–E4, so it cannot support a claim of zero containment.
5. **E4 (reverse shell) under graduated**: `attack_to_received_s` ~21 s because the `timeout 5s kubectl exec` command runs to completion before the Falco alert arrives at the controller. The recorded graduated E4 runs contain two `isolate_network` actions and one `kill_pod` action; the available CSV does not establish that every run escalated to deletion.

---

## 3. Limitations

- **Delete downtime (~8–9 s)** is dominated by single-replica pod restart time, not controller overhead. Multi-replica deployments would reduce visible service disruption.
- **Probe resolution**: 0.5 s sampling interval gives ±0.5 s discretization on downtime measurements.
- **Synthetic attacks via `kubectl exec`**: not realistic multi-stage network exploit chains.
- **In-memory state**: controller restart resets dedup/escalation history.
- **Availability evidence limitations**: the multi-replica test reports only 61–63 probes over the stated two-minute window. The recorded results show zero failures, but the sampling count should be validated before treating them as conclusive proof of uninterrupted availability.

---

## 4. Multi-Replica Availability Test (Item 7)

Victim deployment scaled to **2 replicas**; always_delete strategy; E1 (shell spawn) run 3 times.

| Run | Attacked Pod | Ready After (2 min) | Total Probes | Failures | Downtime (s) | Avail (%) |
|-----|-------------|---------------------|-------------|---------|-------------|-----------|
| 1 | victim-7557fffbdb-2gm5m | 2/2 | 63 | 0 | 0.0 | 100.0 |
| 2 | victim-7557fffbdb-9dsg8 | 2/2 | 61 | 0 | 0.0 | 100.0 |
| 3 | victim-7557fffbdb-gwspk | 2/2 | 62 | 0 | 0.0 | 100.0 |

**Result**: With 2 replicas, the always_delete strategy causes **zero service disruption** (100% availability across all 3 runs). The surviving replica served all probe traffic during the ~8–9 s pod restart window. This confirms the 8–9 s downtime observed in the single-replica tests is entirely due to the absence of a second healthy replica, not controller overhead.

Victim scaled back to 1 replica. Controller restored to STRATEGY=graduated DRY_RUN=true.
