#!/usr/bin/env bash
# scripts/normal-traffic.sh
# Generates 2 min of normal in-cluster traffic and asserts ZERO new RTM alerts.
# Must be run AFTER stub-receiver port-forward is up on $PF_PORT (default 18765).
set -euo pipefail

NS="${SHOP_NS:-shop}"
PF_PORT="${PF_PORT:-18765}"
DURATION="${TRAFFIC_DURATION_SECS:-120}"

echo "==> Snapshotting current RTM alert count..."
BEFORE=$(curl -sf "http://127.0.0.1:${PF_PORT}/alerts/recent" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['count'])")
echo "    alerts before: ${BEFORE}"

echo "==> Generating normal traffic for ${DURATION}s..."
END=$(( $(date +%s) + DURATION ))

# Run a single curl pod that loops hitting all 5 service health+business endpoints
kubectl run normal-traffic \
  --image=curlimages/curl:8.7.1 \
  --restart=Never \
  --namespace="${NS}" \
  --overrides="{
    \"spec\": {
      \"containers\": [{
        \"name\": \"normal-traffic\",
        \"image\": \"curlimages/curl:8.7.1\",
        \"command\": [\"sh\",\"-c\",
          \"while true; do
            curl -sf http://frontend:8000/health        -o /dev/null;
            curl -sf http://frontend:8000/store         -o /dev/null;
            curl -sf http://auth-service:8001/health    -o /dev/null;
            curl -sf http://auth-service:8001/login     -o /dev/null;
            curl -sf http://reviews-service:8002/health -o /dev/null;
            curl -sf http://reviews-service:8002/reviews -o /dev/null;
            curl -sf http://order-service:8003/health   -o /dev/null;
            curl -sf http://order-service:8003/orders   -o /dev/null;
            curl -sf http://payment-service:8004/health -o /dev/null;
            curl -sf http://payment-service:8004/payments -o /dev/null;
            sleep 2;
          done\"]
      }]
    }
  }" --dry-run=client -o yaml | kubectl apply -f -

# Also do one rollout restart mid-traffic
sleep $(( DURATION / 2 ))
echo "    triggering rollout restart of frontend..."
kubectl rollout restart deployment/frontend -n "${NS}"
kubectl rollout status  deployment/frontend -n "${NS}" --timeout=60s

REMAINING=$(( END - $(date +%s) ))
[[ "${REMAINING}" -gt 0 ]] && sleep "${REMAINING}"

kubectl delete pod normal-traffic -n "${NS}" --ignore-not-found

echo "==> Checking RTM alert count after traffic..."
AFTER=$(curl -sf "http://127.0.0.1:${PF_PORT}/alerts/recent" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['count'])")
echo "    alerts after : ${AFTER}"

NEW=$(( AFTER - BEFORE ))
echo "    new RTM alerts during normal traffic: ${NEW}"

if [[ "${NEW}" -gt 0 ]]; then
  echo ""
  echo "FALSE-POSITIVE DETECTED — new alerts:"
  curl -sf "http://127.0.0.1:${PF_PORT}/alerts/recent" \
    | python3 -c "
import sys, json
d = json.load(sys.stdin)
alerts = d.get('alerts', [])
for a in alerts[-${NEW}:]:
    print('  rtm_id=%s rule=%s cmd=%s' % (a.get('rtm_id'), a.get('rule','')[:60], a.get('cmdline','')[:60]))
"
  exit 1
fi

echo "NORMAL TRAFFIC CHECK PASSED — zero false positives"
