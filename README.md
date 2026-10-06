# RTM — Runtime Threat Mitigation in Kubernetes

Detect malicious container behaviour at the syscall level using Falco (eBPF/CO-RE)
on a demo e-commerce application running in Kind.

## Phase Roadmap

| Phase | Description | Status |
|-------|-------------|--------|
| 0     | Environment setup: Kind cluster + demo app (`shop` namespace) | 🔲 In Progress |
| 1     | Falco baseline: Helm install, modern_ebpf driver, Falcosidekick, stub receiver | 🔲 Planned |
| 1.5   | Custom RTM rules (RTM-001–RTM-008), attack simulation, verification | 🔲 Planned |
| 2     | Response engine (auto kill-pod / isolate-network) | ⏸ Out of Scope |
| 3     | Policy engine (Kyverno integration) | ⏸ Out of Scope |

## Repository Layout

```
cluster/               Kind cluster config
manifests/
  demo-app/            FastAPI microservices (shop namespace)
  falco/               Falco Helm values + custom rules
  stub-receiver/       Alert receiver manifests
controller/
  stub-receiver/       FastAPI stub receiver source
scripts/               setup-cluster.sh  install-falco.sh  simulate-attacks.sh  verify-rtm-rules.sh
tests/                 pytest unit tests
docs/                  Architecture, rule docs, known issues
```

## Quick Start

> Prerequisites: Docker Desktop (WSL2 integration enabled), kind, kubectl, helm, gh

```bash
# 1. Create Kind cluster + deploy demo app
./scripts/setup-cluster.sh

# 2. Install Falco + Falcosidekick + stub receiver
./scripts/install-falco.sh

# 3. Run verification suite
./scripts/verify-rtm-rules.sh
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Kind cluster: rtm-k8s-cluster                          │
│                                                          │
│  namespace: shop                                         │
│  ┌──────────┐ ┌──────┐ ┌─────────┐ ┌───────┐ ┌───────┐ │
│  │ frontend │ │ auth │ │ reviews │ │ order │ │payment│ │
│  └──────────┘ └──────┘ └─────────┘ └───────┘ └───────┘ │
│                                                          │
│  namespace: falco                                        │
│  ┌─────────────────┐      ┌──────────────────┐          │
│  │ Falco DaemonSet │─────▶│  Falcosidekick   │          │
│  │  (modern_ebpf)  │      │                  │          │
│  └─────────────────┘      └────────┬─────────┘          │
│                                    │ POST /alerts        │
│                           ┌────────▼────────┐           │
│                           │  stub-receiver  │           │
│                           │   (shop ns)     │           │
│                           └─────────────────┘           │
└─────────────────────────────────────────────────────────┘
```

## Environment

- OS: Ubuntu 24.04 (WSL2), kernel 6.6.x (eBPF/BTF capable)
- Kind: v0.24.0 — node image `kindest/node:v1.31.0`
- Falco: Helm chart pinned (modern_ebpf, CO-RE — no kernel headers needed)
- Python: 3.12
