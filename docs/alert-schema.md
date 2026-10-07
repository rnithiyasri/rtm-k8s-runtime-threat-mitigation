# Alert Schema — Normalized RTM Alert

This document is the **contract between the stub-receiver (Phase 1) and the
response engine (Phase 2)**. Do not change field names or types without bumping
a schema version.

## Endpoint

```
GET /alerts/recent          → { "count": N, "alerts": [ <Alert>, ... ] }
POST /alerts                ← Falcosidekick webhook (Falco JSON)
```

## Alert Object

```json
{
  "ts":            "2026-10-07T13:32:18.971533912Z",
  "rtm_id":        "RTM-003",
  "rule":          "RTM-003 ServiceAccount token read in shop container",
  "priority":      "Critical",
  "tags":          ["T1528", "credential_access", "response_isolate_network", "rtm"],
  "response_hint": "isolate_network",
  "namespace":     "shop",
  "pod":           "order-service-56c4ddb468-896xz",
  "container_id":  "8c7c3b5408ae",
  "user":          "<NA>",
  "cmdline":       "cat /var/run/secrets/kubernetes.io/serviceaccount/token",
  "hostname":      "rtm-k8s-cluster-worker"
}
```

## Field Reference

| Field | Type | Source | Description |
|-------|------|--------|-------------|
| `ts` | ISO-8601 string | `body.time` | Event timestamp from Falco |
| `rtm_id` | string | parsed from `rule` | e.g. `RTM-003` |
| `rule` | string | `body.rule` | Full Falco rule name |
| `priority` | string | `body.priority` | Falco priority: Debug/Info/Notice/Warning/Error/Critical |
| `tags` | string[] | `body.tags` | Falco rule tags; includes MITRE T-number and response hint |
| `response_hint` | string | parsed from tags | `alert_only` / `kill_pod` / `isolate_network` |
| `namespace` | string\|null | `output_fields["k8s.ns.name"]` | Kubernetes namespace |
| `pod` | string\|null | `output_fields["k8s.pod.name"]` | Pod name |
| `container_id` | string\|null | `output_fields["container.id"]` | Short container ID |
| `user` | string\|null | `output_fields["user.name"]` | Process user (`<NA>` if unknown) |
| `cmdline` | string\|null | `output_fields["proc.cmdline"]` | Full command line |
| `hostname` | string\|null | `body.hostname` | Node hostname where Falco fired |

## Response Hints

| Hint | Intended Phase 2 Action |
|------|------------------------|
| `alert_only` | Log and notify only; no enforcement |
| `kill_pod` | Delete the offending pod immediately |
| `isolate_network` | Apply a NetworkPolicy that blocks all ingress/egress |

## Non-RTM Alerts

Alerts whose rule name does not begin with `RTM-` are logged to stderr and
**not stored** in the ring buffer. They will not appear in `/alerts/recent`.

## Ring Buffer

The last **200** RTM alerts are kept in memory. On service restart the buffer
is empty. For persistence, Phase 2 should write to a backing store.
