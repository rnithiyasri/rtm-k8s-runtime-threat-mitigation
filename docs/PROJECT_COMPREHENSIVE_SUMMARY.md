# Runtime Threat Mitigation in Kubernetes (RTM_Kubernetes)
## Complete Comprehensive Reference Document for Team & Project Records

---

### 1. Executive Summary & Project Identification

- **Project Title:** Runtime Threat Mitigation in Kubernetes Using eBPF-Based Detection and Graduated Autonomous Response (RTM_Kubernetes)
- **Repository:** `~/rtm-k8s-runtime-threat-mitigation`
- **Active Working Branch:** `feat/phase2-response-engine` (Tracking: `origin/feat/phase2-response-engine`)
- **Pull Request:** PR #3 (`Feat/phase2 response engine` targeting base `develop`, Status: Open / Awaiting final merge)
- **Latest Recorded Commit:** `88a573b` (*"docs(eval): qualify inconsistent evaluation findings"*)
- **Target Platform:** Kubernetes v1.31 on Kind (WSL2 Linux Kernel 6.6.87 / Ubuntu), Docker CE
- **Core Security Stack:** Falco v0.38+ (modern_ebpf / CO-RE driver, Helm chart 9.2.0), Falcosidekick (v0.14.0), Custom Python FastAPI Response Engine, Kubernetes Client API (`client.CoreV1Api`, `client.NetworkingV1Api`)

---

### 2. High-Level System Architecture

```
+---------------------------------------------------------------------------------------------------+
| Kind Multi-Node Cluster: rtm-k8s-cluster (1 Control-Plane + 1 Worker Node)                         |
|                                                                                                   |
|  Namespace: shop (Target Workload Domain - Opt-in label: rtm.enforce=true)                        |
|  +---------------------------------------------------------------------------------------------+  |
|  | [frontend]   [auth]   [reviews]   [order]   [payment]   [victim-deployment]                 |  |
|  +---------------------------------------------------------------------------------------------+  |
|                                    | (Containerized Syscalls)                                     |
|                                    v                                                              |
|  Namespace: falco (Kernel-Level Observability Domain)                                             |
|  +-------------------------------------+      +------------------------------------------------+  |
|  | Falco DaemonSet (modern_ebpf engine)| ---> | Falcosidekick (Webhook Router)                 |  |
|  | - Evaluates RTM-001 to RTM-008      |      | - Dispatches JSON alert payloads               |  |
|  +-------------------------------------+      +------------------------------------------------+  |
|                                                              | POST http://rtm-controller/alerts   |
|                                                              v                                    |
|  Namespace: shop / default (Autonomous Mitigation Plane)                                          |
|  +---------------------------------------------------------------------------------------------+  |
|  | RTM Response Engine Controller (FastAPI + Kubernetes Client SDK)                             |  |
|  |  - Alert Ingestion & Schema Normalization                                                    |  |
|  |  - In-Memory Deduplication: (rtm_id, container_id, timestamp)                                |  |
|  |  - Strategy Evaluator: [detect_only | graduated | always_delete]                             |  |
|  |  - Enforcement Engine:                                                                       |  |
|  |       * alert_only      -> Audit logging & metrics recording                                 |  |
|  |       * isolate_network -> Dynamic NetworkPolicy injection (Ingress/Egress drop)             |  |
|  |       * kill_pod        -> CoreV1Api delete_namespaced_pod (GracePeriod=0s)                  |  |
|  +---------------------------------------------------------------------------------------------+  |
+---------------------------------------------------------------------------------------------------+
```

---

### 3. Chronological Evolution & Completed Milestones

#### Phase 0: Infrastructure & Workload Orchestration (100% Completed)
- Provisioned a 2-node local Kubernetes cluster (`rtm-k8s-cluster`) using Kind v0.24.0.
- Containerized and deployed a 5-microservice e-commerce application in the `shop` namespace (FastAPI services: `frontend`, `auth`, `reviews`, `order`, `payment`).
- Configured service discovery, cluster networking via Kindnet (v20241108), and workload readiness probes.

#### Phase 1: eBPF Detection Pipeline & Telemetry Routing (100% Completed)
- Deployed Falco 9.2.0 with the modern eBPF driver (`modern_ebpf` engine) leveraging Kernel CO-RE (Compile Once - Run Everywhere).
- Resolved WSL2-specific kernel limitations by implementing and automating `manifests/falco/hostpid-patch.yaml` (`hostPID: true`) to resolve process tree inspection fallbacks.
- Deployed Falcosidekick (v0.14.0) to convert raw Falco syscall events into structured JSON webhooks.
- Implemented an initial `stub-receiver` service exposing `/alerts` and `/alerts/recent` for telemetry ingest.

#### Phase 1.5: Custom RTM Rule Engineering & Adversary Emulation (90% Completed)
- Developed and deployed eight dedicated RTM threat detection rules mapped to MITRE ATT&CK for Containers:
  - **RTM-001:** Terminal / Shell execution inside running container (`sh`, `bash`, `zsh`).
  - **RTM-002:** Unauthorized credential and shadow file access (`/etc/shadow`, `/etc/security`).
  - **RTM-003:** ServiceAccount API token reading (`/var/run/secrets/kubernetes.io/serviceaccount/token`).
  - **RTM-004:** Ingress/Egress network reconnaissance tools (`curl`, `wget`, `nc`, `nmap`).
  - **RTM-005:** Execution of staged binaries from writeable ephemeral paths (`/tmp`, `/dev/shm`).
  - **RTM-006:** Tampering with container package managers (`apt`, `apk`, `dpkg`, `yum`).
  - **RTM-007:** Outbound interactive reverse shell establishment (`/dev/tcp`, interactive socket redirection).
  - **RTM-008:** Unauthorized crypto-mining executable launch (`xmrig`, mining signatures).
- Implemented automated attack emulation harness (`scripts/simulate-attacks.sh`) and baseline verification script (`scripts/verify-rtm-rules.sh`).

#### Phase 2: Autonomous Response Controller & Decision Logic (85% Completed)
- Engineered the response controller in Python/FastAPI (`controller/engine/decision.py`, `controller/engine/main.py`).
- Supported Strategies:
  1. `detect_only`: Telemetry observation and logging without active cluster intervention.
  2. `always_delete`: Immediate destructive pod termination upon any threat alert.
  3. `graduated`: Risk-proportionate response. Initial threats receive network isolation (`isolate_network`), while critical or recurring threats escalate to pod deletion (`kill_pod`).
- Safety Mechanisms:
  - Dry-run mode (`DRY_RUN=true/false`).
  - Opt-in enforcement targeting via label selector (`rtm.enforce=true`).
  - In-memory event deduplication across sliding time windows.
- Automated Test Suite: Developed and executed comprehensive test suite in `tests/test_decision.py` — **14/14 automated unit tests passing (100% pass rate)**.
- Pull Request #3 opened and retargeted to `develop`.

#### Phase 2.5 / 5: Empirical Benchmarking & Audit (75% Completed)
- Executed 36-run benchmark suite across 4 attack scenarios (E1: Shell spawn, E2: Token read, E3: Temp binary, E4: Reverse shell) across 3 strategies.
- Evaluated key performance indicators: controller decision latency (18–45 ms), downtime, service availability, and containment state.
- Conducted multi-replica resilience validation: demonstrated that scaling victim pods to 2 replicas achieves **100% service availability and 0.0s downtime** even under destructive `always_delete` policies.
- Conducted critical scientific audit of evaluation data (`docs/evaluation-summary.md`): identified labeling discrepancies and measurement caveats to ensure strict academic integrity.

---

### 4. Detailed Test Results & Empirical Metrics

#### A. Decision Engine Unit Tests
- Command: `python -m pytest tests/test_decision.py -v -p no:cacheprovider`
- Results: **14 passed in 0.08s**
- Validated behaviors:
  - Clean separation between strategies (`detect_only`, `graduated`, `always_delete`).
  - Accurate graduated escalation from `isolate_network` to `kill_pod` upon threshold breaches.
  - Proper handling of deduplication windows driven by controller monotonic time.
  - Correct enforcement of label selector barriers preventing unauthorized pod mutation.

#### B. Benchmark Latency & Availability Findings
- **Controller Decision Latency:** Controller internal processing (`received_to_action_s`) consistently achieved **18 ms to 45 ms**, verifying negligible algorithmic overhead.
- **Graduated Containment:** Under `graduated`, E1 and E2 maintained **100.0% availability with 0.0 s downtime**, isolating network egress without taking the application offline.
- **Destructive Deletion Overhead:** Single-replica pod deletion under `always_delete` resulted in ~8–9 seconds of service downtime during pod rescheduling (~68–71% availability).
- **Multi-Replica Resilience:** When configured with 2 replicas, the service absorbed pod eviction with **0.0 s downtime and 100.0% availability**, proving that single-replica downtime is an infrastructure scheduling artifact, not a controller delay.

---

### 5. Technical Challenges, Audit Findings & Known Limitations

To maintain absolute academic rigor, the following findings and limitations must be clearly understood:

1. **Evaluation CSV Strategy Label Discrepancy:**
   - In `docs/evaluation-results.csv`, 12 runs are designated under the column label `alert_only`.
   - The engine's formal strategy identifier is `detect_only` (`alert_only` is an individual response action).
   - Furthermore, rows within this group record active enforcement actions (`isolate_network` for E2 and `kill_pod` for E3).
   - *Status:* Correctly documented in `docs/evaluation-summary.md` as "unresolved strategy attribution." These rows must not be presented as baseline unmitigated tests.
2. **End-to-End Alert Forwarding Verification:**
   - Syscall detection in Falco was verified for RTM-001 through RTM-008.
   - However, during the final live cluster check, the receiver endpoint `/alerts` did not register expected HTTP POST requests from Falcosidekick.
   - *Root cause:* Network webhook routing or sidekick buffer configuration requires end-to-end verification in the active cluster session.
3. **WSL2 Kernel eBPF Iterators (KI-001):**
   - Microsoft WSL2 kernel 6.6.87 lacks support for BPF task/socket iterators. Falco issues a non-fatal warning and falls back to `/proc` scanning.
   - Mitigated via `hostpid-patch.yaml`.
4. **Single-Host Kind eBPF Alert Duplication (KI-002):**
   - In Kind, control-plane and worker nodes run as Docker containers on the same physical kernel. Both Falco DaemonSet pods monitor the identical eBPF buffer, producing 2x identical alerts.
   - Mitigated via controller deduplication on `(rtm_id, container_id, timestamp)`.
5. **Probe Sampling Resolution:**
   - The 2-minute availability check registered 61–63 HTTP probes instead of the theoretical 240 probes (at 0.5s intervals). While 0 downtime was recorded, the probe sampling script needs timing calibration.

---

### 6. Immediate Action Plan for Next Working Session

1. **Restore & Verify End-to-End Forwarding:** Deploy and test webhook connectivity from Falcosidekick to RTM Controller in `rtm-k8s-cluster` to ensure live alerts reach `/alerts`.
2. **Execute Clean Evaluation Re-Run:** Execute a clean 36-run benchmark run with unambiguous strategy flags (`detect_only`, `graduated`, `always_delete`) and backup previous CSV logs.
3. **Pull Request Review & Merge:** Finalize code review on PR #3 and merge `feat/phase2-response-engine` into `develop`.
4. **Update Repository Documentation:** Finalize root `README.md` with updated architectural diagrams, reproducible evaluation steps, and verified benchmark graphs.
