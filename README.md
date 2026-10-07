# RTM — Runtime Threat Mitigation in Kubernetes

Detect malicious container behaviour at the syscall level using **Falco
(modern eBPF / CO-RE)** on a demo e-commerce application running in Kind.
Alerts are routed through **Falcosidekick** to a **stub-receiver** that
normalises and stores them for a future response engine.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Kind cluster: rtm-k8s-cluster  (1 control-plane + 1 worker)   │
│                                                                 │
│  namespace: shop                                                │
│  ┌──────────┐ ┌──────┐ ┌─────────┐ ┌───────┐ ┌──────────┐     │
│  │ frontend │ │ auth │ │ reviews │ │ order │ │ payment  │     │
│  └──────────┘ └──────┘ └─────────┘ └───────┘ └──────────┘     │
│        │           │         │          │           │           │
│        └───────────┴─────────┴──────────┴───────────┘          │
│                          syscalls                               │
│                             │                                   │
│  namespace: falco           ▼                                   │
│  ┌──────────────────┐   ┌──────────────────┐                   │
│  │  Falco DaemonSet │──▶│  Falcosidekick   │                   │
│  │  (modern_ebpf)   │   │  chart 0.14.0    │                   │
│  │  chart 9.2.0     │   └────────┬─────────┘                   │
│  └──────────────────┘            │ POST /alerts                │
│                                  ▼                              │
│                       ┌─────────────────────┐                  │
│                       │   stub-receiver     │                  │
│                       │   GET /alerts/recent│                  │
│                       │   (shop namespace)  │                  │
│                       └─────────────────────┘                  │
└─────────────────────────────────────────────────────────────────┘
```

## Phase Roadmap

| Phase | Description | Status |
|-------|-------------|--------|
| 0 | Kind cluster + demo app (`shop` namespace, 5 FastAPI services) | ✅ Done |
| 1 | Falco baseline: Helm install, modern_ebpf, Falcosidekick, stub-receiver | ✅ Done |
| 1.5 | Custom RTM rules (RTM-001–RTM-008), attack sim, verify, docs | ✅ Done |
| 2 | Response engine (kill-pod / isolate-network) | ⏸ Out of Scope |
| 3 | Policy engine (Kyverno integration) | ⏸ Out of Scope |

## Prerequisites

| Tool | Version |
|------|---------|
| Docker Desktop (WSL2 backend, **containerd image store OFF**) | 4.x |
| kind | v0.24.0 |
| kubectl | v1.34+ |
| helm | v4.x |
| git + gh | any recent |
| Python | 3.11+ |

> WSL2 note: disable "Use containerd for pulling and storing images" in Docker
> Desktop → Settings → General, otherwise `kindest/node` image extraction
> fails. See `docs/known-issues.md` KI-007.

## Quick Start

```bash
# 1. Clone
git clone https://github.com/rnithiyasri/rtm-k8s-runtime-threat-mitigation.git
cd rtm-k8s-runtime-threat-mitigation

# 2. Create Kind cluster and deploy demo app
bash scripts/setup-cluster.sh

# 3. Install Falco + Falcosidekick + stub-receiver
bash scripts/install-falco.sh

# 4. Verify all RTM rules fire correctly
bash scripts/verify-rtm-rules.sh

# 5. (Optional) Run attack simulations manually
bash scripts/simulate-attacks.sh all

# 6. (Optional) False-positive check
# In one terminal: kubectl port-forward -n shop svc/stub-receiver 18765:8000
# In another:      bash scripts/normal-traffic.sh
```

## Repository Layout

```
cluster/                      Kind cluster config
manifests/
  demo-app/                   FastAPI service source + K8s manifests
  falco/                      Falco Helm values, custom rules, hostPID patch
  stub-receiver/              Stub-receiver K8s Deployment + Service
controller/
  stub-receiver/              FastAPI stub-receiver source
scripts/
  setup-cluster.sh            Create cluster, build images, deploy shop app
  install-falco.sh            Install Falco + Falcosidekick + stub-receiver
  simulate-attacks.sh         Benign attack simulations for all RTM rules
  verify-rtm-rules.sh         PASS/FAIL verification table
  normal-traffic.sh           False-positive check (2 min normal traffic)
tests/
  test_stub_receiver.py       pytest unit tests (no cluster needed)
docs/
  rtm-custom-rules.md         Threat model, how to add/validate rules
  alert-schema.md             Normalized alert JSON contract for Phase 2
  known-issues.md             WSL2 quirks, duplicate alerts, etc.
```

## Running Tests

```bash
python3 -m venv .venv
.venv/bin/pip install fastapi uvicorn pytest httpx
.venv/bin/pytest tests/ -v
```

## Key Design Decisions

- **modern_ebpf driver**: no kernel headers or module compilation needed; works
  on WSL2 kernel 6.6.x with BTF/vmlinux present.
- **rule_matching: all**: allows multiple RTM rules to fire on the same event
  (e.g., RTM-001 + RTM-007 on a reverse-shell exec). Causes duplicate alerts
  per event — see `docs/known-issues.md` KI-002 and KI-004.
- **response_hint tag**: each rule carries `response_alert_only`, `kill_pod`,
  or `isolate_network` so a Phase 2 engine can act without parsing rule names.
- **Stub receiver ring buffer**: last 200 RTM alerts kept in memory at
  `GET /alerts/recent`. Non-RTM alerts are logged only.
