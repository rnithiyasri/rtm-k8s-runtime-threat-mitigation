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

Empirical testing on kind (Kubernetes v1.31 with Calico/modern_ebpf Falco) revealed several critical runtime characteristics:

1. **Established TCP Connections Survive Network Isolation**:
   - Applying `rtm.tier=restrict` or `rtm.tier=quarantine` to a running pod **does not sever existing established TCP sockets**.
   - In capability tests B1 and B2, active client and server connections delivered 100% of packets (155/155 and 133/133 pings across 120s) while new incoming and outgoing connections were blocked.
   - *Implication*: NetworkPolicy alone cannot terminate an already established attacker C2 reverse shell. Terminating interactive sessions requires pod deletion (`kill_pod`) or container killing.
2. **Ingress Restriction Flapping on Running Pods**:
   - Testing inbound quarantine on running pods showed unreliability and flapping (inbound probes succeeded in multiple test intervals). Therefore, Phase 2 implements **egress restriction only** via `rtm-restrict`.
3. **Startup Flapping on Pods Created with Restrict Labels**:
   - When a replacement pod is created with `rtm.tier=restrict` pre-set, a race condition during CNI interface provisioning permits a 0–12 second window of traffic leakage before network policies lock down. Running pods labeled dynamically achieve deterministic enforcement within 1–3 seconds.
4. **In-Memory State**:
   - Decision engine history, deduplication timestamps, and action records reside entirely in-memory within the controller container. A controller pod restart resets history and counters.
5. **Dropped Alert Metadata**:
   - The normalized alert contract ingested by the controller extracts pod name, container ID, rule ID, and command-line, but drops raw packet data such as dynamic destination IP and port numbers.
