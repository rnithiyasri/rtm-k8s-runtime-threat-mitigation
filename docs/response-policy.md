# RTM Response Policy (Phase 2)

This document describes the **actions, escalation rules, safety guards, and known
limitations** of the runtime response engine deployed in Phase 2.

---

## 1. Response Hint-to-Action Mapping

Falco rules in Phase 1.5 tag each alert with a `response_<hint>` tag. The response
controller maps these hints directly to Kubernetes actions without hardcoding rule
names:

| Response Hint | Action | Controller Mechanism | Intended Threat Class |
|---|---|---|---|
| `alert_only` | Log only | Records decision in ring buffer and logs JSON decision line. No Kubernetes changes. | Low-confidence or observational indicators (e.g., interactive shell spawn `RTM-001`, sensitive file read `RTM-002`, package manager run `RTM-004`). |
| `isolate_network` | Isolate network | Patches target pod metadata with label `rtm.tier=restrict`. NetworkPolicy `rtm-restrict` drops egress to public IPs while preserving intra-namespace traffic and DNS. | Data exfiltration attempts (`RTM-006`) and ServiceAccount token theft (`RTM-003`). |
| `kill_pod` | Delete pod | Issues `DELETE` to Kubernetes CoreV1 API for the target pod. ReplicaSet controller automatically provisions a fresh replacement. | Critical active threats: reverse shell execution (`RTM-007`), temp directory binary execution (`RTM-005`), and crypto-miner execution (`RTM-008`). |

---

## 2. Escalation & Deduplication Rules

- **Multi-Rule Escalation**: If a pod triggers **3 or more DIFFERENT `rtm_id` rules
  within a rolling 300-second window**, the controller escalates the action to
  `kill_pod` (deleting the pod), regardless of whether the individual alerts were
  `alert_only` or `isolate_network`. The escalation check runs **before** the
  isolation-suppression guard so that already-isolated pods correctly escalate on a
  third distinct rule (fix: commit `637e54b`).
- **10-Second Deduplication**: Consecutive alerts with the identical `(pod, rtm_id)`
  tuple within 10 seconds of each other are deduplicated and ignored to prevent alert
  flooding. Both the deduplication window and the 300-second rolling window use the
  **controller's own receive clock** (`time.time()`), not `alert_ts` from Falco, so
  they are immune to Falco clock skew (commit `14367df`).
- **Action Non-Repetition**: The controller never repeats an action already executed:
  - If a pod has already been patched with `isolate_network`, subsequent isolate or
    alert-only alerts do not re-patch. Escalation to `kill_pod` still fires on a
    **third distinct rule**.
  - If a pod has already been deleted (`kill_pod`), all subsequent alerts are
    suppressed.

---

## 3. Safety Guards

The response engine operates under strict defense-in-depth safety controls:

1. **Dry-Run by Default (`DRY_RUN=true`)**: The controller defaults to dry-run mode.
   When dry-run is active, it evaluates the decision and outputs `WOULD <action> pod
   <name>` in structured JSON logs without executing any Kubernetes mutations.
2. **Opt-In Workload Label Selector (`ENFORCE_LABEL_SELECTOR=rtm.enforce=true`)**:
   Even when `DRY_RUN=false` is set globally, the controller **only** acts on pods
   carrying the explicit label `rtm.enforce: "true"`. Unlabeled pods (production shop
   services) remain strictly dry-run, preventing accidental outages.
3. **Strict Namespace Boundary**: The controller only evaluates alerts and executes
   actions within namespace `shop`. Alerts from `kube-system`, `default`, or
   `rtm-tools` are filtered out.
4. **Isolated Namespace Execution**: The controller runs in `rtm-system` under a
   dedicated `ServiceAccount rtm-controller` with least-privilege RBAC (Role in `shop`
   granting `get`, `list`, `patch`, `delete` on `pods` only; no `ClusterRole`). Running
   in `rtm-system` prevents the controller from triggering Falco rules on itself.

---

## 4. Measured Limitations & Empirical Findings

Empirical testing on kind (Kubernetes v1.31, kindnet v20241108, modern_ebpf Falco):

1. **Established Connections Survived QUARANTINE Label**:
   - Applying `rtm.tier=quarantine` to a running pod did NOT sever existing established
     TCP sockets (155/155 and 133/133 pings delivered across 120 s).
   - Egress restriction (`rtm.tier=restrict`) was NOT tested against established
     connections.
   - *Implication*: NetworkPolicy alone cannot terminate an established attacker C2
     reverse shell. Terminating interactive sessions requires pod deletion (`kill_pod`).
2. **Flapping and Asymmetric Enforcement in Quarantine Tests (B1 & B2)**:
   - New outbound connections from the labelled client were blocked for ~140 s, then
     succeeded again at t+153 s; inbound connections to the labelled server were never
     blocked.
   - Consequently the quarantine tier is **not implemented (dropped)**.
3. **Deterministic Egress Restriction on Running Pods**:
   - Dynamic egress restriction (`rtm.tier=restrict`) on a running pod blocked new
     egress in 1-3 s and held across 60/60 probes.
4. **Startup Flapping on Pods Created with Restrict Labels**:
   - A replacement pod created with `rtm.tier=restrict` pre-set has a 0-12 s window of
     traffic leakage during CNI provisioning. Running pods labelled dynamically achieve
     deterministic enforcement within 1-3 s.
5. **Delete Downtime (~8-9 s)**:
   - Pod deletion and single-replica ReplicaSet restart imposes ~8-9 s of service
     downtime. This is primarily the pod scheduling and container start time, not
     controller overhead. Availability in `always_delete` strategy drops to ~67-71%.
6. **In-Memory State**:
   - Decision engine history (deduplication timestamps, action records) resides entirely
     in-memory. A controller pod restart resets all state.
7. **Dropped Alert Metadata**:
   - The normalized alert contract extracts pod name, container ID, rule ID, and
     command-line, but drops raw packet data (destination IP/port).
8. **Escalation Suppression Bug (Fixed in commit `637e54b`)**:
   - *Original defect*: In commit `c0c3de1`, the isolation suppression check ran
     **before** the 3-rule escalation threshold, so isolated pods never escalated on
     `alert_only`-hint rules.
   - *Fix*: The multi-rule escalation check (`len(unique_rtms) >= 3`) now runs first.
     Live test confirmed: RTM-001 -> isolate_network, RTM-003 (dup, suppressed),
     RTM-002 -> kill_pod with reason `escalation_3_different_rules`.
9. **Falco Clock Skew After Host Suspend/Resume (WSL2)**:
   - `alert_ts` in Falco alerts uses the kernel eBPF monotonic clock, which freezes
     during WSL2 VM suspend. After resume, `alert_ts` can lag wall time by hours
     (observed offset: ~45,560 s / ~12.66 h after a laptop sleep cycle).
   - The controller uses `time.time()` (controller receive clock) for all deduplication
     and window arithmetic; `alert_ts` is retained in logs only for traceability.
   - Evaluation metrics (`attack_to_received_s`, `received_to_action_s`,
     `attack_to_action_s`) are all single-clock (WSL host clock vs controller
     `time.time()`) to eliminate cross-clock artifacts.

---

## 5. Pull Request Description

### Phase 2 - Graduated Runtime Response Engine

**What this PR adds:**

- `controller/engine/decision.py`: Graduated decision engine with hint mapping,
  10 s deduplication, 300 s multi-rule escalation, and action non-repetition. All
  timing state uses the controller receive clock; `alert_ts` is log-only.
- `controller/engine/main.py`: FastAPI webhook listener; receives Falcosidekick JSON,
  normalises fields, calls decision engine, executes K8s mutations (label patch /
  pod delete) guarded by `DRY_RUN` and `rtm.enforce=true` selector.
- `k8s/`: NetworkPolicy `rtm-restrict`, RBAC Role/RoleBinding, Deployment, Service,
  and ServiceAccount manifests for the controller.
- `scripts/evaluate.sh`: Evaluation harness running configurable strategies
  (`alert_only`, `graduated`, `always_delete`) across 4 attack scenarios (E1-E4)
  with single-clock metrics and preflight Falco clock drift check.
- `docs/evaluation-results.csv` + `docs/evaluation-summary.md`: Empirical results
  from 36-run evaluation (REPEATS=3, 3 strategies x 4 scenarios).
- `tests/test_decision.py`: 22 unit tests covering hint mapping, deduplication,
  escalation (including escalation-after-isolation), and controller-clock isolation.

**Key design decisions:**

- Escalation check runs **before** isolation suppression (fixes commit `c0c3de1` bug).
- All window/dedupe arithmetic uses controller clock only - immune to Falco WSL2 skew.
- `DRY_RUN=true` default + `rtm.enforce=true` label gate - production pods safe.

**What was NOT tested:**

- `restrict` label against already-established TCP connections.
- Multi-replica controller state sync (controller is single-replica, in-memory state).
- Root cause of NetworkPolicy enforcement flapping observed in quarantine tests.
- Ingress restriction against running pods.
