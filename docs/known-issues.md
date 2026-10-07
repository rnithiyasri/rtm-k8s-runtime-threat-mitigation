# Known Issues and Limitations

## WSL2 / Kind Specific

### KI-001 — BPF iterators disabled warning

**Symptom:** Every Falco pod logs:
```
[libs]: libpman: disabled BPF iterators (not running in the root PID namespace, or failed to determine it)
```
**Cause:** The WSL2 kernel (6.6.87.x-microsoft-standard-WSL2) does not support
BPF task/socket iterators even when `hostPID: true` is set on the pod. The
iterators are used to pre-populate the process table at startup; without them
Falco falls back to `/proc` lookups.

**Impact:** Process ancestry (`proc.pname`, `proc.aname`) may be `<NA>` for
processes that started before Falco did. Syscall-level event detection still
works correctly.

**Workaround:** Apply `manifests/falco/hostpid-patch.yaml` after every Helm
install/upgrade (already automated in `scripts/install-falco.sh`). On a real
Linux node (non-WSL2) this issue does not occur.

---

### KI-002 — Duplicate alerts per event (2×)

**Symptom:** Each Falco event produces two identical alerts in stub-receiver
(one from each DaemonSet pod — control-plane and worker).

**Cause:** Kind creates a 2-node cluster. Both Falco pods share the same eBPF
ring buffer because they both attach to the same kernel on the same VM. This
is a Kind/single-VM artefact; on a real multi-node cluster each pod only sees
events from its own node.

**Impact:** Alert count is doubled; stub-receiver deduplication is not
implemented (out of scope for Phase 1).

**Workaround:** In Phase 2 deduplicate on `(rtm_id, container_id, ts)` before
taking action.

---

### KI-003 — hostPID not exposed by Falco chart 9.2.0

**Symptom:** `helm show values falcosecurity/falco --version 9.2.0` has no
`hostPID` key.

**Cause:** The chart manages pod-spec fields internally and does not expose
`hostPID` as a configurable value.

**Fix:** `kubectl patch daemonset falco -n falco --patch-file manifests/falco/hostpid-patch.yaml`
is applied by `scripts/install-falco.sh` after every Helm install/upgrade.

---

### KI-004 — RTM-007 produces multiple alerts per event

**Symptom:** A single `bash -i >& /dev/tcp/...` attempt fires RTM-007 four or
more times.

**Cause:** `rule_matching: all` is enabled (required so RTM-001 and RTM-007
can both fire on the same exec event). Each `dup`/`dup2`/`dup3` syscall that
redirects fd 0, 1, or 2 fires the rule independently. A typical reverse shell
issues at least three such calls.

**Impact:** Cosmetic — results in redundant alerts, not missed ones.

**Workaround:** Phase 2 should deduplicate on `(rtm_id, container_id)` within
a short time window before taking action.

---

### KI-005 — RTM-008 co-fires RTM-005 for /tmp/xmrig

**Symptom:** The RTM-008 simulation (`cp /bin/sleep /tmp/xmrig && /tmp/xmrig 1`)
also fires RTM-005 (binary executed from /tmp).

**Cause:** This is correct behaviour — executing any binary from `/tmp` matches
RTM-005 regardless of the filename. A real miner staged in `/tmp` should trigger
both rules.

**Impact:** None — the co-fire is intentional and documented.

---

### KI-006 — RTM-002 requires root (non-root containers)

**Symptom:** `cat /etc/shadow` from a non-root container returns `Permission
denied` at the OS level before Falco can see the open syscall.

**Cause:** `/etc/shadow` is mode 640 root:shadow. A non-root process is denied
by the kernel before issuing the `openat` syscall that Falco monitors.

**Impact:** RTM-002 fires on the `open_attempt` (the `openat` syscall is still
issued even when the kernel will deny it). Verified: Falco sees the syscall and
fires the rule. The exit code of `cat` is non-zero but the alert is generated.

---

### KI-007 — Docker Desktop containerd image store breaks kindest/node

**Symptom:** Kind node container starts then immediately exits with
`exec format error`; all binaries in the image are 0 bytes.

**Cause:** Docker Desktop's containerd image store (enabled via
Settings → General → "Use containerd for pulling and storing images") uses the
overlayfs snapshotter which incorrectly handles opaque whiteout layers in the
`kindest/node` image.

**Fix:** Disable the containerd image store in Docker Desktop settings and
re-pull the image. The classic `overlay2` driver handles the image correctly.
