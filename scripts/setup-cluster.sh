#!/usr/bin/env bash
# scripts/setup-cluster.sh  –  idempotent Kind cluster + shop namespace bootstrap
set -euo pipefail

CLUSTER_NAME="rtm-k8s-cluster"
KIND_CONFIG="$(dirname "$0")/../cluster/kind-config.yaml"
MANIFESTS="$(dirname "$0")/../manifests/demo-app"
SERVICES="frontend auth-service reviews-service order-service payment-service"

echo "==> Checking Kind cluster..."
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
  echo "    Cluster '${CLUSTER_NAME}' already exists – skipping creation."
else
  echo "    Creating cluster '${CLUSTER_NAME}'..."
  kind create cluster --config "${KIND_CONFIG}"
fi

echo "==> Verifying nodes..."
kubectl wait --for=condition=Ready nodes --all --timeout=120s
kubectl get nodes

echo "==> Creating namespace 'shop'..."
kubectl create namespace shop --dry-run=client -o yaml | kubectl apply -f -

echo "==> Building demo-app images..."
for svc in ${SERVICES}; do
  echo "    Building ${svc}..."
  docker build -t "${svc}:latest" "${MANIFESTS}/${svc}"
  echo "    Loading ${svc} into Kind..."
  kind load docker-image "${svc}:latest" --name "${CLUSTER_NAME}"
done

echo "==> Deploying demo-app manifests..."
kubectl apply -f "${MANIFESTS}/manifests/" -n shop

echo "==> Waiting for all pods in shop to be Ready..."
kubectl wait --for=condition=Ready pods --all -n shop --timeout=120s

echo "==> Final status:"
kubectl get pods -n shop
echo ""
echo "setup-cluster.sh DONE"
