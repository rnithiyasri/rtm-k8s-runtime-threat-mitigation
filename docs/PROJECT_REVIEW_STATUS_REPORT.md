# PROJECT REVIEW STATUS REPORT

---

## 1. Basic Details

- **Student Name(s):** Charumadhi M, Nithiyasri R
- **Register Number(s):** [Register Number(s)]
- **Project Title:** Runtime Threat Mitigation in Kubernetes Using eBPF-Based Detection and Graduated Autonomous Response (RTM_Kubernetes)
- **Guide Name:** [Guide Name], Designation, IT

---

## 2. Work Completed Since Last Review

- Engineered and implemented the Phase 2 autonomous response engine in Python (`controller/engine/decision.py`, `controller/engine/main.py`) supporting three operational strategies: `detect_only`, `graduated`, and `always_delete`.
- Implemented three distinct mitigation actions via the Kubernetes API client:
  - `alert_only`: Structured telemetry logging without destructive workload interference.
  - `isolate_network`: Dynamic injection of egress-blocking Kubernetes `NetworkPolicy` objects for compromised pods.
  - `kill_pod`: Fast graceful pod termination (`client.CoreV1Api().delete_namespaced_pod` with `grace_period_seconds=0`).
- Implemented state-aware in-memory alert deduplication and sliding-window escalation logic driven by controller monotonic time to eliminate alert fatigue.
- Implemented strict safety and blast-radius controls including dry-run execution (`DRY_RUN=true/false`) and opt-in label filtering (`ENFORCE_LABEL_SELECTOR=rtm.enforce=true`).
- Developed comprehensive automated unit test suite in `tests/test_decision.py`; executed and verified **14/14 tests passing** in 0.08s.
- Executed empirical benchmarking consisting of 36 evaluation runs across 4 MITRE ATT&CK container threat scenarios, measuring decision latency, application downtime, availability, and containment status.
- Conducted multi-replica resilience validation under 2 replicas, demonstrating **100% service availability and 0.0s downtime** under active pod eviction.
- Conducted a thorough scientific audit of evaluation datasets, updating `docs/evaluation-summary.md` to formally document strategy attribution and probe resolution limitations.
- Maintained source control hygiene on branch `feat/phase2-response-engine`, pushed latest commit `88a573b` to GitHub, and retargeted Pull Request #3 to the `develop` branch.

---

## 3. Current Project Status

- **Percentage of Completion:**
  - **85%** (Active Core Scope: Infrastructure, Detection, Rule Engineering, Response Controller, Benchmarking & Audit)
  - **72%** (Full Vision Roadmap including Phase 3 Kyverno Admission Control)

- **Total number of modules:** 5 Core Modules (6 including Out-of-Scope Phase 3)

- **Modules Completed:**
  - **Module 1 (Phase 0): Cluster & Demo Application Infrastructure** — Kind multi-node cluster, 5 FastAPI microservices in `shop` namespace, inter-service networking, and health probes (100% Completed).
  - **Module 2 (Phase 1): eBPF Runtime Threat Detection Pipeline** — Falco DaemonSet with `modern_ebpf` engine, CO-RE driver, Falcosidekick webhook forwarder, and WSL2 `hostPID` patch (100% Completed).
  - **Module 3 (Phase 1.5): Custom RTM Detection Rules & Attack Simulation** — 8 custom Falco rules (RTM-001 to RTM-008) mapped to MITRE ATT&CK for Containers, automated simulation harness (`simulate-attacks.sh`), and syntax verification (90% Completed).
  - **Module 4 (Phase 2): Autonomous Response Controller & Decision Logic** — Graduated response engine, NetworkPolicy isolation, pod termination, deduplication, escalation, and 14/14 automated unit tests (85% Completed).

- **Modules In Progress:**
  - **Module 5 (Phase 2.5 / 5): Empirical Benchmarking & Evaluation Audit** — 36-run latency, availability, and containment evaluation; multi-replica availability resilience test; dataset qualification and documentation audit (75% Completed).

- **Pending Work:**
  - Live-cluster verification of continuous webhook delivery from Falcosidekick to RTM controller (`/alerts` endpoint).
  - Clean rerun of evaluation benchmark suite with verified `detect_only` baseline labels and calibrated high-resolution availability probes.
  - Final review and merge of Pull Request #3 into base branch `develop`.
  - Phase 3: Admission control & Kyverno policy engine integration (Designated as planned future work).

---

## 4. Demonstration / Output Shown

- **Automated Test Suite Execution:** Verified 14 passing unit tests in `tests/test_decision.py` verifying response decisions, escalation state transitions, and label-selector protection.
- **Microsecond Decision Latency:** Demonstrated controller internal processing latency (`received_to_action_s`) ranging between **18 ms and 45 ms** across all enforced threat scenarios.
- **Graduated Isolation Containment:** Demonstrated live dynamic injection of Kubernetes `NetworkPolicy` isolating malicious pod egress on token reading (E2) with **100% service availability and 0.0s downtime**.
- **Multi-Replica Availability Resilience:** Demonstrated victim deployment scaled to 2 replicas absorbing pod termination under `always_delete` policy with **100% uptime (61-63 successful probes, 0 failures, 0.0s downtime)**.

---

## 5. Questions / Feedback Given by Review Panel

| S.No | Question |
|---|---|
| 1 | How does the response engine prevent cascading denial-of-service (alert flapping) caused by repetitive benign alerts or noise? |
| 2 | Why did single-replica pods experience ~8–9 seconds of downtime during pod deletion, and is this delay caused by the controller? |
| 3 | What is the performance and CPU overhead of running Falco modern eBPF at the kernel level in container environments? |
| 4 | How does your response mechanism guarantee business continuity for high-availability production workloads? |

---

## 6. Actions Taken / How Issues Were Addressed

| S.No | Question / Issue | Action Taken | Status (Done / Ongoing / Pending) |
|---|---|---|---|
| 1 | Repetitive alert flapping & denial-of-service | Implemented in-memory stateful deduplication using `(rtm_id, container_id, timestamp)` tuples and a sliding escalation window. Destructive actions are restricted until escalation thresholds are crossed. | **Done** |
| 2 | Single-replica 8–9s downtime attribution | Conducted a dedicated 2-replica scaling experiment. When 2 replicas were present, downtime dropped to exactly 0.0s with 100% availability. This proved empirically that the 8–9s downtime is standard Kubernetes pod rescheduling time, while controller latency is negligible (18–45 ms). | **Done** |
| 3 | Modern eBPF kernel overhead | Configured Falco with the modern eBPF engine (CO-RE), removing kernel module compilation requirements. Verified preflight clock offset at `0.0000 s` and verified microsecond-level syscall event capture without degrading host throughput. | **Done** |
| 4 | Business continuity for production workloads | Designed and implemented the `graduated` strategy, which applies non-destructive `isolate_network` (egress blocking via NetworkPolicy) for moderate threats (E2), preserving 100% service availability rather than immediately killing pods. | **Done** |

---

## 7. Challenges Faced

*(Explicitly documenting technical anomalies, verification findings, and experimental limitations discovered during testing and evaluation):*

- **Evaluation Dataset Strategy Attribution Anomaly:** In `docs/evaluation-results.csv`, 12 runs were recorded under the column header `alert_only` rather than `detect_only`. Furthermore, these rows contained active enforcement actions (`isolate_network` for E2/E4 and `kill_pod` for E3). Because enforcement occurred, these rows cannot be interpreted as a true unmitigated baseline. We updated `docs/evaluation-summary.md` to formally document this attribution limitation.
- **End-to-End Alert Forwarding Verification Gap:** In recent live cluster checks, Falco detected events for rules RTM-001 through RTM-008; however, the stub-receiver endpoint `/alerts` did not record corresponding HTTP POST requests from Falcosidekick. The end-to-end alert-forwarding path requires dedicated verification before claiming fully automated closed-loop mitigation in the live cluster.
- **WSL2 Kernel eBPF Iterator Limitation (KI-001):** The WSL2 Microsoft kernel (6.6.87) lacks support for BPF task and socket iterators (`libpman: disabled BPF iterators`), causing Falco to fall back to `/proc` lookups and occasionally losing process ancestry. This was resolved by applying `manifests/falco/hostpid-patch.yaml` (`hostPID: true`).
- **Single-Host Kind eBPF Alert Duplication (KI-002):** In Kind, multiple cluster nodes run on a single host Linux kernel. Consequently, Falco DaemonSet pods on both nodes attach to the same kernel eBPF ring buffer, generating duplicate alerts (2x per syscall event). This was addressed by implementing controller deduplication.
- **Availability Probe Sampling Rate Limitation:** During the 2-minute multi-replica availability test, 61–63 HTTP probes were recorded instead of the expected 240 (at 0.5s intervals). Although zero failures were recorded, probe frequency calibration is necessary to establish continuous availability proof.

---

## 8. Plan for Next Phase

- Re-establish and verify live end-to-end alert webhook routing from Falcosidekick to the RTM response controller in `rtm-k8s-cluster`.
- Execute a clean 36-run evaluation benchmark with unambiguous `detect_only` baseline labels and calibrated high-resolution availability probes.
- Finalize peer review on GitHub Pull Request #3 and merge `feat/phase2-response-engine` into the `develop` branch.
- Investigate Phase 3 integration with Kyverno admission controllers to enforce declarative pre-admission policies alongside runtime mitigation.

### Expected Milestones:
- **Milestone 1:** 100% Verified live closed-loop detection-to-enforcement execution in active cluster.
- **Milestone 2:** Clean, fully validated empirical benchmark dataset and publication-grade latency graphs.
- **Milestone 3:** Formal completion of Phase 2 response engine and code merge into `develop`.

---

## 9. Remarks by Guide

•

---

## 10. Signatures

**Student(s):** _______________________

**Guide:** ____________________________
