# RTM Evaluation Summary (Phase 5)

This document summarizes the empirical evaluation of the Runtime Threat Mitigation (RTM) engine comparing three response strategies across four attack scenarios.

---

## 1. Median Metrics per Strategy x Scenario

Evaluated on `rtm-k8s-cluster` (Kubernetes v1.31, kindnet v20241108, Falco modern_ebpf) with $n=2$ runs per cell:

| Strategy | Scenario | Action Logged | Final State (`contained`) | Median Detection (s) | Median Containment (s) | Median Downtime (s) | Median Availability (%) |
|---|---|---|---|---|---|---|---|
| `detect_only` | E1 (shell spawn) | `alert_only` | `open` | 0.732 | - | 0.0 | 100.0 |
| `detect_only` | E2 (token read) | `alert_only` | `open` | 0.657 | - | 0.0 | 100.0 |
| `detect_only` | E3 (tmp binary) | `alert_only` | `open` | 0.562 | - | 0.0 | 100.0 |
| `detect_only` | E4 (reverse shell) | `alert_only` | `open` | 0.654 | - | 0.0 | 100.0 |
| `always_delete` | E1 (shell spawn) | `kill_pod` | `deleted` | 0.671 | 0.001 | 8.8 | 68.8 |
| `always_delete` | E2 (token read) | `kill_pod` | `deleted` | 0.654 | 0.001 | 8.5 | 70.2 |
| `always_delete` | E3 (tmp binary) | `kill_pod` | `deleted` | 0.656 | 0.001 | 8.5 | 70.2 |
| `always_delete` | E4 (reverse shell) | `kill_pod` | `deleted` | 0.661 | 0.001 | 9.0 | 69.5 |
| `graduated` | E1 (shell spawn) | `alert_only` | `open` | 0.673 | - | 0.0 | 100.0 |
| `graduated` | E2 (token read) | `alert_only`* | `egress_blocked` | 0.682 | - | 0.0 | 100.0 |
| `graduated` | E3 (tmp binary) | `alert_only`* | `deleted` | 0.788 | - | 9.2 | 67.6 |
| `graduated` | E4 (reverse shell) | `alert_only`* | `deleted` | 0.812 | - | 7.5 | 77.2 |

*\*Note: In scenarios E2, E3, and E4, executing the command via `sh -c` or `bash -c` first triggered `RTM-001` (shell spawn, `alert_only`) as the earliest alert line; subsequent alerts within the invocation triggered network isolation (`rtm.tier=restrict` in E2) and pod deletion (`kill_pod` in E3/E4).*

---

## 2. Reading of Results

1. **Graduated strategy preserved availability on low/medium threats**: In E1 and E2, `graduated` maintained 100.0% availability with 0.0s downtime, whereas `always_delete` suffered ~8.5–8.8s downtime (dropping availability to ~68.8–70.2%).
2. **Deterministic isolation without service interruption**: For E2 (token read), `graduated` successfully enforced network egress lockdown (`egress_blocked`) while leaving the inbound service endpoint fully responsive.
3. **Always-delete is an unguided disruption hammer**: Deleting the pod on every alert guarantees containment (`deleted`) for all scenarios, but imposes substantial availability penalties across benign or observational events (E1/E2).
4. **Detect-only provides zero mitigation**: Across all four attack scenarios, `detect_only` left the victim pod completely `open` with 0% containment.
5. **Detection latency is sub-second across all modes**: Median detection latency across all strategies and scenarios ranged between 0.56s and 0.85s, with sub-millisecond containment response upon rule evaluation.

---

## 3. Evaluation Limitations

- **Sample Size**: Small sample size ($n=2$ per cell) designed for validation rather than high statistical power.
- **Single Replica / Single Victim Pod**: Testing targeted a single victim deployment replica; multi-replica load distribution was not evaluated.
- **Synthetic Attack Probes**: Attack vectors were simulated directly via `kubectl exec` CLI invocations rather than realistic multi-stage network exploit chains.
- **Probe Resolution**: Service availability was sampled at 0.5-second intervals via `curlimages/curl` loop, giving a $\pm 0.5\text{s}$ measurement discretization on downtime.
- **Clock Synchronization**: Timestamps reflect single-node kind/WSL environment clocks; distributed multi-node clock skew was not modeled.

---

## 4. Hypothesis Verification

- **Graduated keeps victim available on E1 and E2**: **HELD** (100.0% availability, 0.0s downtime on both).
- **Always-delete drops availability on E1 and E2**: **HELD** (availability dropped to 68.8% on E1 and 70.2% on E2).
- **Detect-only leaves the victim "open"**: **HELD** (100.0% of runs left in state `open`).
- **Deviations / Observations**: Launching simulated attacks via `sh -c` / `bash -c` in E2–E4 triggered RTM-001 (shell spawned) milliseconds before RTM-003/005/007, meaning `alert_only` was recorded as the earliest logged action before graduated isolation/escalation took effect.
