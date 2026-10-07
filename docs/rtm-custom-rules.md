# RTM Custom Falco Rules

## Threat Model

| ID | Rule Name | Attack Scenario | MITRE ATT&CK | Why It Matters | Known False Positives | Response Hint |
|----|-----------|-----------------|--------------|----------------|----------------------|---------------|
| RTM-001 | Shell spawned in shop container | Attacker drops a reverse shell or interactive session | T1059.004 Execution | Any interactive shell in a production container is anomalous | `kubectl exec` for debugging — tune by adding a `not k8s.pod.label.debug=true` condition | alert_only |
| RTM-002 | Sensitive file read | Attacker reads `/etc/shadow`, `/etc/sudoers`, SSH keys for credential harvesting | T1555 / T1003 Credential Access | Credentials in containers are a common pivot point | None expected in shop pods | alert_only |
| RTM-003 | ServiceAccount token read | Attacker reads the K8s SA token to call the Kubernetes API | T1528 Steal Application Access Token | SA token gives cluster-level access if RBAC is weak | Application frameworks that auto-read the token at startup — add their proc names to `rtm_sa_token_allowed_procs` | isolate_network |
| RTM-004 | Package manager / download tool | Attacker installs tools or downloads payloads at runtime | T1105 Ingress Tool Transfer | Runtime package install breaks immutability guarantees | CI/CD init containers — scope by namespace | alert_only |
| RTM-005 | Binary exec from /tmp, /dev/shm, /var/tmp | Attacker stages and runs a payload from a writable temp dir | T1036 Masquerading / T1059 | Executables in temp dirs are a classic malware staging pattern | None in shop pods; also fires for RTM-008 (documented) | kill_pod |
| RTM-006 | Outbound connection to public IP | Data exfiltration or C2 callback | T1041 Exfiltration Over C2 | Shop pods have no legitimate reason to connect to public internet | Add trusted IPs/CIDRs to `rtm_egress_allowed_ips` | isolate_network |
| RTM-007 | Reverse shell (stdio → socket) | Shell with stdin/stdout/stderr redirected to a network socket | T1059 Command and Scripting Interpreter | Classic reverse-shell indicator | None expected | kill_pod |
| RTM-008 | Crypto-miner indicator | Known miner process name or connection to common mining ports | T1496 Resource Hijacking | Crypto mining wastes resources and indicates full compromise | None — miner binary names are highly specific | kill_pod |

## Adding a New Rule

1. Add the rule to `manifests/falco/rtm-custom-rules.yaml`.
2. Follow the existing output template:
   ```
   "RTM-00X <name> ns=%k8s.ns.name pod=%k8s.pod.name container=%container.name
    cid=%container.id user=%user.name proc=%proc.name cmd=%proc.cmdline parent=%proc.pname"
   ```
3. Include tags: `[rtm, <mitre_tactic>, <T-number>, response_<hint>]`
4. Validate offline before deploying (see next section).
5. Run `helm upgrade` to deploy.
6. Run `scripts/verify-rtm-rules.sh` to confirm it fires.
7. Run `scripts/normal-traffic.sh` to confirm no false positives.

## Validate a Rule Offline

```bash
# Find the Falco app version for the pinned chart
helm show chart falcosecurity/falco --version 9.2.0 | grep appVersion
# → appVersion: 0.45.0

# Validate (no cluster needed)
docker run --rm \
  -v "$(pwd)/manifests/falco:/rules:ro" \
  falcosecurity/falco:0.45.0 \
  falco --validate /rules/rtm-custom-rules.yaml
```

Expected output: `Ok` with no errors.

## Reload After Changes

```bash
helm upgrade falco falcosecurity/falco \
  --namespace falco \
  --version 9.2.0 \
  --values manifests/falco/falco-values.yaml \
  --reuse-values

# Re-apply the WSL2 hostPID patch
kubectl patch daemonset falco -n falco \
  --patch-file manifests/falco/hostpid-patch.yaml
kubectl rollout restart daemonset/falco -n falco
kubectl rollout status  daemonset/falco -n falco --timeout=120s
```
