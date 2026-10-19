# RTM Response Engine Policy (Phase 2)

This document describes the design, response mappings, escalation rules, safety guards, and empirical limitations of the Runtime Threat Mitigation (RTM) Graduated Response Engine in Kubernetes.

---

## 1. Response Hint-to-Action Mapping

Falco rules in Phase 1.5 tag each alert with a `response_<hint>` tag. The response controller maps these hints directly to Kubernetes actions without hardcoding rule names:

| Response Hint | Action | Controller Mechanism | Intended Threat Class |
|---|---|---|---|
| `alert_only` | Log only | Records decision in ring buffer and logs JSON decision line. No Kubernetes changes. | Low-confidence or observational indicators (e.g., interactive shell spawn `RTM-001`, sensitive file read `RTM-002`, package manager run `RTM-004`). |
| `isolate_network` | Isolate network | Patches target pod metadata with label `rtm.tier=restrict`. NetworkPolicy `rtm-restrict` drops egress to public IPs while preserving intra-namespace traffic and DNS. | Data exfiltration attempts (`RTM-006`) and ServiceAccount token theft (`RTM-003`). |
| `kill_pod` | Delete pod | Issues `DELETE` to Kubernetes CoreV1 API for the target pod. ReplicaSet controller automatically provisions a fresh replacement. | Critical active threats: reverse shell execution (`RTM-007`), temp directory binary execution (`RTM-005`), and crypto-miner execution (`RTM-008`). |

---

## 2. Escalation & Deduplication Rules

- **Multi-Rule Escalation**: If a pod triggers **3 or more DIFFERENT `rtm_id` rules within a rolling 300-second window**, the controller escalates the action to `kill_pod` (deleting the pod), regardless of whether the individual alerts were `alert_only` or `isolate_network`.
- **10-Second Deduplication**: Consecutive alerts with the identical `(pod, rtm_id)` tuple within 10 seconds of each other are deduplicated and ignored to prevent alert flooding.
- **Action Non-Repetition**: The controller never repeats an action already executed on a pod:
  - If a pod has already been patched with `isolate_network`, subsequent isolate or alert-only alerts do not re-patch or prematurely delete the pod under inspection.
  - If a pod has already been deleted (`kill_pod`), subsequent alerts during its termination phase are suppressed.

---

## 3. Safety Guards

The response engine operates under strict defense-in-depth safety controls:

1. **Dry-Run by Default (`DRY_RUN=true`)**: The controller defaults to dry-run mode. When dry-run is active, it evaluates the decision and outputs `WOULD <action> pod <name>` in structured JSON logs without executing any Kubernetes mutations.
2. **Opt-In Workload Label Selector (`ENFORCE_LABEL_SELECTOR=rtm.enforce=true`)**: Even when `DRY_RUN=false` is set globally, the controller **only** acts on pods carrying the explicit label `rtm.enforce: "true"`. Unlabeled pods (such as production shop services: `auth-service`, `frontend`, `order-service`, `payment-service`, `reviews-service`) remain strictly dry-run (`WOULD ...`), preventing accidental outages.
3. **Strict Namespace Boundary**: The controller only evaluates alerts and executes actions within namespace `shop`. Alerts from `kube-system`, `default`, or `rtm-tools` are filtered out.
4. **Isolated Namespace Execution**: The controller runs in namespace `rtm-system` under a dedicated ServiceAccount `rtm-controller` with least-privilege RBAC (Role in `shop` granting `get`, `list`, `patch`, `delete` on `pods` only; no `ClusterRole`). Running in `rtm-system` prevents the controller from triggering Falco rules (e.g. `RTM-003`) on itself.

---

## 4. Measured Limitations & Empirical Findings

Empirical testing on kind (Kubernetes v1.31 with kindnet v20241108 / modern_ebpf Falco) revealed several critical runtime characteristics:

1. **Established Connections Survived QUARANTINE Label**:
   - Applying `rtm.tier=quarantine` to a running pod did NOT sever existing established TCP sockets: active client and server connections survived (155/155 and 133/133 pings delivered across 120 s).
   - Egress restriction (`rtm.tier=restrict`) was **NOT tested against established connections**.
   - *Implication*: NetworkPolicy alone cannot be assumed to terminate an already established attacker C2 reverse shell. Terminating interactive sessions requires pod deletion (`kill_pod`).
2. **Flapping and Asymmetric Enforcement in Quarantine Tests (B1 & B2)**:
   - In Test B1: new outbound connections from the labelled client were blocked for about 140 s, then succeeded again at t+153 s.
   - In Test B2: new inbound connections to the labelled server were NOT blocked in any of 12 samples.
   - Enforcement flapped in tests A2 and B1, cause unknown.
   - Consequently, the quarantine tier is **not implemented (dropped)**.
3. **Deterministic Egress Restriction on Running Pods**:
   - In contrast to quarantine, dynamic egress restriction (`rtm.tier=restrict`) on a running pod blocked new egress in 1 to 3 s in Test A1 and in 60/60 probes in S2.
4. **Startup Flapping on Pods Created with Restrict Labels**:
   - When a replacement pod is created with `rtm.tier=restrict` pre-set, a race condition during CNI interface provisioning permits a 0–12 second window of traffic leakage before network policies lock down. Running pods labeled dynamically achieve deterministic enforcement within 1–3 seconds.
5. **In-Memory State**:
   - Decision engine history, deduplication timestamps, and action records reside entirely in-memory within the controller container. A controller pod restart resets history and counters.
6. **Dropped Alert Metadata**:
   - The normalized alert contract ingested by the controller extracts pod name, container ID, rule ID, and command-line, but drops raw packet data such as dynamic destination IP and port numbers.
7. **Escalation Suppression on Isolated Pods (Empirical Defect)**:
   - In live testing, after a pod was isolated via `isolate_network` (triggered by `RTM-001` + `RTM-003`), executing a third distinct rule (`RTM-002 Sensitive file read`, hint `alert_only`) did **not** escalate to `kill_pod`. The pod remained running in namespace `shop`.
   - *Root Cause*: Commit `c0c3de1` placed the isolation suppression check (`if "isolate_network" in taken and planned_action != "kill_pod": return None`) before the escalation threshold check (`if len(unique_rtms) >= 3`). Because `planned_action` from hint is `alert_only`, the controller drops the alert before evaluating multi-rule escalation.
8. **Clock Domain Differences in Latency Metrics**:
   - `alert_ts` is recorded on the Falco daemon clock (kernel monotonic / eBPF timestamp), whereas `received_ts` and `action_done_ts` are recorded on the controller's user-space clock.
   - Cross-clock subtraction (`alert_to_action_s = action_done_ts - alert_sec`) can produce sub-millisecond artifacts or clock skew under host sleep/resume cycles.
   - Internal controller execution overhead (`received_to_action_s = action_done_ts - received_ts`) reliably measures 20–44 ms from webhook ingestion to Kubernetes API mutation.

---

## 5. Pull Request Description Draft

### Summary of Changes
- Implements graduated response controller in `controller/engine/` listening to Falcosidekick webhook events.
- Evaluates rules via hint mapping (`alert_only`, `isolate_network`, `kill_pod`) with 10s deduplication and multi-rule escalation.
- Enforces egress network isolation via `rtm-restrict` NetworkPolicy and pod deletion via CoreV1 API.
- Implements strict safety guards: `DRY_RUN=true` by default, `rtm.enforce=true` opt-in label selector, and `shop` namespace containment.
- Implements evaluation harness in `scripts/evaluate.sh` benchmarking `detect_only`, `always_delete`, and `graduated` strategies across 4 attack scenarios with dual-clock timing metrics (`alert_to_action_s` and `received_to_action_s`).

### Known Issues & What Was NOT Tested
- **Known Issue**: Escalation to `kill_pod` fails on pods that have already been isolated with `isolate_network` if the third rule has an `alert_only` hint (due to isolation suppression preceding the escalation check in commit `c0c3de1`).
- `restrict` (`rtm.tier=restrict`) against established TCP connections.
- Root cause of flapping observed during quarantine tests A2 and B1.
- Ingress restriction against running pods.
- Multi-replica controller state synchronization (controller is currently single-replica in-memory).
