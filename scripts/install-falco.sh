#!/usr/bin/env bash
# scripts/install-falco.sh
# Installs Falco 9.2.0 + Falcosidekick 0.14.0 + stub-receiver.
# Idempotent: safe to re-run.
set -euo pipefail

CLUSTER_NAME="rtm-k8s-cluster"
FALCO_CHART_VERSION="9.2.0"
FALCOSIDEKICK_CHART_VERSION="0.14.0"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "==> Adding falcosecurity Helm repo..."
helm repo add falcosecurity https://falcosecurity.github.io/charts 2>/dev/null || true
helm repo update

echo "==> Creating namespace falco..."
kubectl create namespace falco --dry-run=client -o yaml | kubectl apply -f -

echo "==> Installing Falco (chart ${FALCO_CHART_VERSION}, Falco 0.45.0)..."
helm upgrade --install falco falcosecurity/falco \
  --namespace falco \
  --version "${FALCO_CHART_VERSION}" \
  --values "${REPO_ROOT}/manifests/falco/falco-values.yaml" \
  --wait --timeout 5m

# WSL2 FIX: chart does not expose hostPID; patch it so BPF iterators work
# Without this Falco logs "disabled BPF iterators (not running in root PID namespace)"
# and captures zero syscalls from other containers.
echo "==> Patching Falco DaemonSet: hostPID=true (required on WSL2)..."
kubectl patch daemonset falco -n falco \
  --patch-file "${REPO_ROOT}/manifests/falco/hostpid-patch.yaml"
kubectl rollout status daemonset/falco -n falco --timeout=120s

echo "==> Installing Falcosidekick (chart ${FALCOSIDEKICK_CHART_VERSION})..."
helm upgrade --install falco-falcosidekick falcosecurity/falcosidekick \
  --namespace falco \
  --version "${FALCOSIDEKICK_CHART_VERSION}" \
  --values "${REPO_ROOT}/manifests/falco/falcosidekick-values.yaml" \
  --wait --timeout 3m

echo "==> Building stub-receiver image..."
docker build -t stub-receiver:latest "${REPO_ROOT}/controller/stub-receiver"
kind load docker-image stub-receiver:latest --name "${CLUSTER_NAME}"

echo "==> Deploying stub-receiver..."
kubectl apply -f "${REPO_ROOT}/manifests/stub-receiver/deployment.yaml"
kubectl rollout status deployment/stub-receiver -n shop --timeout=60s

echo ""
echo "==> Falco pods:"
kubectl get pods -n falco
echo ""
echo "==> Stub-receiver:"
kubectl get pods -n shop -l app=stub-receiver
echo ""
echo "install-falco.sh DONE"
