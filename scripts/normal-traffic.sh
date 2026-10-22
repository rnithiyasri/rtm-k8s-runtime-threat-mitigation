#!/usr/bin/env bash
# scripts/normal-traffic.sh
# Generates normal in-cluster traffic from namespace 'rtm-tools'
# and asserts ZERO new RTM alerts are triggered in namespace 'shop'.
set -euo pipefail

SHOP_NS="${SHOP_NS:-shop}"
RECEIVER_NS="${RECEIVER_NS:-${SHOP_NS}}"
RECEIVER_SVC="${RECEIVER_SVC:-stub-receiver}"
TOOLS_NS="${TOOLS_NS:-rtm-tools}"
PF_PORT="${PF_PORT:-18765}"
DURATION="${TRAFFIC_DURATION_SECS:-120}"

# ── Ensure tools namespace exists ─────────────────────────────────────────────
kubectl create namespace "${TOOLS_NS}" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

# ── Ensure stub-receiver port-forward is active ───────────────────────────────
PF_PID=""
if ! curl -sf "http://127.0.0.1:${PF_PORT}/healthz" >/dev/null 2>&1; then
  echo "==> Starting port-forward to stub-receiver on port ${PF_PORT}..."
  kubectl port-forward -n "${RECEIVER_NS}" "svc/${RECEIVER_SVC}" "${PF_PORT}:8000" >/dev/null 2>&1 &
  PF_PID=$!
  sleep 2
fi

cleanup() {
  echo "==> Cleaning up normal-traffic pod..."
  kubectl delete pod normal-traffic -n "${TOOLS_NS}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  if [[ -n "${PF_PID}" ]]; then
    kill "${PF_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

# ── Record newest alert timestamp before the run ──────────────────────────────
echo "==> Recording newest alert timestamp before traffic..."
LATEST_TS_BEFORE=$(curl -sf "http://127.0.0.1:${PF_PORT}/alerts/recent" \
  | python3 -c "
import sys, json
data = json.load(sys.stdin)
alerts = data.get('alerts', [])
ts_list = [a.get('ts') for a in alerts if a.get('ts')]
print(max(ts_list) if ts_list else '')
")
echo "    latest alert ts before: ${LATEST_TS_BEFORE:-<none>}"

# ── Launch traffic generator pod in rtm-tools ─────────────────────────────────
echo "==> Deploying traffic generator pod in '${TOOLS_NS}'..."
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: normal-traffic
  namespace: ${TOOLS_NS}
  labels:
    app: normal-traffic
spec:
  restartPolicy: Never
  containers:
  - name: normal-traffic
    image: curlimages/curl:8.7.1
    command:
    - sh
    - -c
    - |
      while true; do
        curl -sf http://frontend.${SHOP_NS}:8000/health        -o /dev/null || true
        curl -sf http://frontend.${SHOP_NS}:8000/store         -o /dev/null || true
        curl -sf http://auth-service.${SHOP_NS}:8001/health    -o /dev/null || true
        curl -sf http://auth-service.${SHOP_NS}:8001/login     -o /dev/null || true
        curl -sf http://reviews-service.${SHOP_NS}:8002/health -o /dev/null || true
        curl -sf http://reviews-service.${SHOP_NS}:8002/reviews -o /dev/null || true
        curl -sf http://order-service.${SHOP_NS}:8003/health   -o /dev/null || true
        curl -sf http://order-service.${SHOP_NS}:8003/orders   -o /dev/null || true
        curl -sf http://payment-service.${SHOP_NS}:8004/health -o /dev/null || true
        curl -sf http://payment-service.${SHOP_NS}:8004/payments -o /dev/null || true
        sleep 2
      done
EOF

kubectl wait --for=condition=Ready pod/normal-traffic -n "${TOOLS_NS}" --timeout=30s >/dev/null

echo "==> Generating normal traffic for ${DURATION}s..."
END=$(( $(date +%s) + DURATION ))

# Mid-run rollout restart of frontend
sleep $(( DURATION / 2 ))
echo "    triggering rollout restart of frontend in ${SHOP_NS}..."
kubectl rollout restart deployment/frontend -n "${SHOP_NS}"
kubectl rollout status deployment/frontend -n "${SHOP_NS}" --timeout=60s

REMAINING=$(( END - $(date +%s) ))
[[ "${REMAINING}" -gt 0 ]] && sleep "${REMAINING}"

echo "==> Stopping traffic generator pod..."
kubectl delete pod normal-traffic -n "${TOOLS_NS}" --ignore-not-found >/dev/null 2>&1 || true

# ── Assert zero new RTM alerts ────────────────────────────────────────────────
echo "==> Checking for alerts generated after timestamp: ${LATEST_TS_BEFORE:-<none>}..."
STATUS=0
curl -sf "http://127.0.0.1:${PF_PORT}/alerts/recent" \
  | python3 -c "
import sys, json

latest_before = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] else ''
data = json.load(sys.stdin)
alerts = data.get('alerts', [])

new_alerts = []
for a in alerts:
    ts = a.get('ts', '')
    if not latest_before or ts > latest_before:
        new_alerts.append(a)

if new_alerts:
    print(f'FALSE-POSITIVE DETECTED — {len(new_alerts)} new alert(s):')
    for a in new_alerts:
        print(f\"  rtm_id={a.get('rtm_id')} pod={a.get('pod')} cmdline={a.get('cmdline')}\")
    sys.exit(1)
else:
    print('NORMAL TRAFFIC CHECK PASSED — zero false positives')
    sys.exit(0)
" "${LATEST_TS_BEFORE}" || STATUS=$?

exit "${STATUS}"
