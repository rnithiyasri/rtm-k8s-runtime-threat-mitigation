# RTM — Runtime Threat Mitigation in Kubernetes

Autonomous cloud-native runtime security for Kubernetes. Detects malicious container behaviour at the kernel system call level using **Falco (modern eBPF / CO-RE)** and executes risk-proportionate, low-latency mitigation actions via an autonomous **Response Engine**.

---

## Architecture

```
+---------------------------------------------------------------------------------------------------+
| Kind Cluster: rtm-k8s-cluster (1 Control-Plane + 1 Worker Node)                                   |
|                                                                                                   |
|  Namespace: shop (Monitored Workloads - Opt-in: rtm.enforce=true)                                 |
|  +---------------------------------------------------------------------------------------------+  |
|  | [frontend]   [auth]   [reviews]   [order]   [payment]   [victim-deployment]                 |  |
|  +---------------------------------------------------------------------------------------------+  |
|                                    | (Containerized Syscalls: execve, openat, socket, connect)     |
|                                    v                                                              |
|  Namespace: falco (Kernel-Level Observability)                                                    |
|  +-------------------------------------+      +------------------------------------------------+  |
|  | Falco DaemonSet (modern_ebpf engine)| ---> | Falcosidekick (Webhook Router)                 |  |
|  | - Evaluates rules RTM-001 - RTM-008 |      | - Dispatches JSON alert payloads               |  |
|  +-------------------------------------+      +------------------------------------------------+  |
|                                                              | POST http://rtm-controller/alerts   |
|                                                              v                                    |
|  Namespace: shop (Autonomous Response & Mitigation Plane)                                         |
|  +---------------------------------------------------------------------------------------------+  |
|  | RTM Response Engine Controller (FastAPI + Kubernetes Client SDK)                             |  |
|  |  - In-Memory Deduplication: (rtm_id, container_id, timestamp)                                |  |
|  |  - Configurable Strategies: [detect_only | graduated | always_delete]                         |  |
|  |  - Enforcement Actions:                                                                     |  |
|  |       * alert_only      --> Telemetry & audit logging                                        |  |
|  |       * isolate_network --> Dynamic NetworkPolicy injection (Ingress/Egress drop)             |  |
|  |       * kill_pod        --> Immediate pod termination (client.CoreV1Api, grace_period=0)    |  |
|  +---------------------------------------------------------------------------------------------+  |
+---------------------------------------------------------------------------------------------------+
```

---

## Phase Roadmap

| Phase | Description | Status |
|---|---|---|
| **0** | Kind cluster + demo microservices (`shop` namespace, 5 FastAPI services) | Completed |
| **1** | Falco baseline: Helm 9.2.0, `modern_ebpf` driver, Falcosidekick, stub-receiver | Completed |
| **1.5** | Custom RTM rules (RTM-001–RTM-008), attack simulation harness, rule verification | Completed |
| **2** | Autonomous Response Engine (`controller/engine/`), graduated strategies, 14 unit tests | Completed |
| **2.5 / 5** | Empirical evaluation: 36-run latency benchmark, multi-replica resilience, evaluation audit | Completed |
| **3** | Policy Engine (Kyverno admission control integration) | Out of Scope / Planned Future |

---

## Prerequisites

| Tool | Version | Notes |
|---|---|---|
| **Docker Desktop** | 4.x+ | WSL2 backend; disable "Use containerd for pulling and storing images" (KI-007) |
| **Kind** | v0.24.0+ | Multi-node local Kubernetes cluster |
| **kubectl** | v1.31+ | Cluster administration CLI |
| **Helm** | v3.12+ | Package manager for Falco & Falcosidekick |
| **Python** | 3.11+ | Controller development & pytest test suite |

---

## Quick Start

### 1. Provision Cluster & Microservices
```bash
# Clone the repository
git clone https://github.com/rnithiyasri/rtm-k8s-runtime-threat-mitigation.git
cd rtm-k8s-runtime-threat-mitigation

# Create Kind cluster and deploy the shop microservices
bash scripts/setup-cluster.sh
```

### 2. Deploy Falco & Telemetry Pipeline
```bash
# Install Falco with modern_ebpf driver + Falcosidekick + hostPID patch
bash scripts/install-falco.sh
```

### 3. Verify Custom Threat Detection Rules
```bash
# Run benign attack simulations against all custom RTM rules
bash scripts/verify-rtm-rules.sh

# Or simulate all attacks manually
bash scripts/simulate-attacks.sh all
```

### 4. Run Controller Automated Unit Tests
```bash
# Activate virtual environment and run the test suite
python3 -m venv .venv
source .venv/bin/activate
pip install -r controller/engine/requirements.txt pytest
python -m pytest tests/test_decision.py -v -p no:cacheprovider
```

---

## Controller Configuration & Strategies

The Phase 2 response engine supports configurable environment variables:

```bash
STRATEGY=graduated          # Options: detect_only | graduated | always_delete
DRY_RUN=true                # true = observe only; false = execute live enforcement
ENFORCE_LABEL_SELECTOR=rtm.enforce=true # Pods must have this label to allow enforcement
```

### Response Actions:
- **`alert_only`**: Records threat telemetry and logs metrics without modifying workloads.
- **`isolate_network`**: Injects a targeted Kubernetes `NetworkPolicy` blocking pod egress while preserving 100% service availability and zero downtime.
- **`kill_pod`**: Executes rapid pod eviction (`delete_namespaced_pod` with 0s grace period) for critical threats.

---

## Repository Layout

```
cluster/                      Kind cluster configuration (1 CP + 1 Worker)
manifests/
  demo-app/                   FastAPI microservices source + K8s Deployment manifests
  falco/                      Falco Helm values, custom RTM rules, hostPID patch
  stub-receiver/              Initial telemetry receiver manifests
controller/
  engine/                     Phase 2 Response Engine source (main.py, decision.py)
  stub-receiver/              FastAPI stub-receiver source
scripts/
  setup-cluster.sh            Provisions Kind cluster & deploys shop microservices
  install-falco.sh            Installs Falco modern_ebpf, Falcosidekick & hostPID patch
  simulate-attacks.sh         Simulates benign MITRE ATT&CK container threats
  verify-rtm-rules.sh         Executes automated detection verification suite
  normal-traffic.sh           Simulates benign traffic for false-positive validation
  evaluate.sh                 Automated 36-run latency, availability & containment benchmark
tests/
  test_decision.py            Automated unit tests for response logic & escalation (14 tests)
  test_stub_receiver.py       Unit tests for alert receiver normalization
docs/
  evaluation-summary.md       Scientific evaluation audit, benchmark tables & data notes
  evaluation-results.csv      Raw 36-run benchmark measurements
  rtm-custom-rules.md         Documentation for rules RTM-001 through RTM-008
  response-policy.md          Policy escalation state machine & decision specification
  known-issues.md             WSL2 quirks, BPF iterators, Kind ring buffer artifacts
  PROJECT_REVIEW_STATUS_REPORT.md  Standardized project review status report
  RESEARCH_PROJECT_REPORT.md       Academic project report (SSN College format)
  PROJECT_COMPREHENSIVE_SUMMARY.md Complete team reference documentation
```

---

## Key Findings & Design Decisions

- **modern_ebpf (CO-RE)**: Eliminates kernel header dependencies and host compilation; verified clock offset of `0.0000 s`.
- **Negligible Controller Latency**: Controller decision processing (`received_to_action_s`) consistently measures **18 ms to 45 ms**.
- **Graduated Containment Preserves Availability**: Isolating network egress on moderate threats maintains **100.0% availability with 0.0 s downtime**, avoiding the ~8–9 s disruption of single-replica pod terminations.
- **Multi-Replica Resilience**: In 2-replica deployments, the service sustains pod terminations with **100% continuous availability and zero downtime**, confirming that pod restart delays are infrastructure scheduling characteristics rather than controller overhead.
- **Controller-Clock Deduplication**: In-memory state machine deduplicates alerts on `(rtm_id, container_id, timestamp)` tuples, eliminating single-host Kind eBPF ring buffer duplicate alerts.
