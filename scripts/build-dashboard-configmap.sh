#!/usr/bin/env bash
# scripts/build-dashboard-configmap.sh
#
# Rebuilds manifests/frontend/configmap.yaml from frontend source files
# and optionally applies it to the running cluster.
#
# Usage:
#   ./scripts/build-dashboard-configmap.sh          # build only
#   ./scripts/build-dashboard-configmap.sh --apply  # build + kubectl apply
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRONTEND="$REPO_ROOT/frontend"
OUT="$REPO_ROOT/manifests/frontend/configmap.yaml"

echo "[build-dashboard] Generating ConfigMap from frontend source files..."

python3 "$REPO_ROOT/scripts/_gen_configmap.py" \
  "$FRONTEND/index.html" \
  "$FRONTEND/app.js" \
  "$FRONTEND/style.css" \
  "$OUT"

echo "[build-dashboard] Wrote: $OUT"

if [[ "${1:-}" == "--apply" ]]; then
  echo "[build-dashboard] Applying ConfigMap to cluster..."
  kubectl apply -f "$OUT"

  echo "[build-dashboard] Restarting rtm-dashboard deployment..."
  kubectl rollout restart deployment/rtm-dashboard -n shop

  echo "[build-dashboard] Waiting for rollout..."
  kubectl rollout status deployment/rtm-dashboard -n shop --timeout=60s

  echo "[build-dashboard] Done. Dashboard updated."
else
  echo "[build-dashboard] Done. Run with --apply to deploy:"
  echo "  kubectl apply -f $OUT"
  echo "  kubectl rollout restart deployment/rtm-dashboard -n shop"
fi
