# RTM Dashboard — Frontend

A real-time, read-only operational dashboard for the **Kubernetes Runtime Threat Mitigation (RTM)** system.

Shows live detection telemetry and automated mitigation actions across all 7 pipeline stages:
1. **Attack Trigger** (human-in-the-loop emulation)
2. **Falco Detection** (kernel eBPF syscall capture)
3. **Falcosidekick Forward** (webhook routing)
4. **Controller Receive / Dedupe** (ring buffer & suppression check)
5. **Decision Evaluation** (graduated strategy state machine)
6. **Safety Gate Barrier** (`rtm.enforce=true` opt-in check & dry-run guard)
7. **Mitigation Action** (`isolate_network` / `kill_pod`)

---

## Architecture & Design Principles

- **Zero dependencies & no build step**: Pure vanilla HTML5, CSS3, and ES6 JavaScript. No Node.js, Vite, or npm packages required.
- **Strictly read-only**: Exclusively queries `GET /alerts/recent`, `GET /pods/status`, and `GET /config`. No write/mutating routes (`POST`, `PUT`, `DELETE`, `PATCH`) exist in the dashboard.
- **No synthetic/fake metrics**: Every counter, status pill, and timestamp originates from live controller polls every 2.5 seconds.
- **Fail-safe staleness indicator**: If the controller becomes unreachable for >10 seconds, the status banner switches to amber/red and marks data stale.

---

## Local Run (Option 1: Direct Browser File)

1. **Port-forward the RTM Controller API**:
   ```bash
   kubectl port-forward svc/rtm-controller -n rtm-system 8000:8000
   ```

2. **Open `index.html`**:
   - Double-click `frontend/index.html` in your file explorer, or
   - Start a simple local HTTP server:
     ```bash
     cd frontend
     python3 -m http.server 8080
     ```
   - Navigate to: `http://localhost:8080` (or `file://.../frontend/index.html`)

The dashboard connects to `http://localhost:8000` automatically. You can also override the API target with the `?api=` query parameter, e.g.:
`http://localhost:8080/?api=http://localhost:8000`

---

## In-Cluster Deployment (Option 2: Kubernetes Manifests)

The dashboard can be deployed as an in-cluster static service using an `nginx:alpine` pod that mounts the static files via a Kubernetes `ConfigMap`:

1. **Apply the manifests**:
   ```bash
   # Create the ConfigMap from the frontend directory
   kubectl create configmap rtm-dashboard-html -n shop \
     --from-file=index.html=frontend/index.html \
     --from-file=app.js=frontend/app.js \
     --from-file=style.css=frontend/style.css \
     --dry-run=client -o yaml | kubectl apply -f -

   # Deploy the Nginx service and deployment
   kubectl apply -f manifests/frontend/deployment.yaml
   kubectl apply -f manifests/frontend/service.yaml
   ```

2. **Port-forward the dashboard**:
   ```bash
   kubectl port-forward svc/rtm-dashboard -n shop 8080:80
   ```

3. Open `http://localhost:8080` in your browser.
