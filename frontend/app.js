/**
 * RTM Dashboard — app.js
 *
 * Polls GET /alerts/recent, GET /pods/status, GET /config every 2 s.
 * Read-only — no POST/DELETE/PATCH calls.  No framework, no build step.
 * All numbers shown on the page come from live polls — no constants.
 *
 * CORS note: the controller must have CORSMiddleware enabled (allow_origins
 * includes "null" for file:// and the localhost ports).
 */

'use strict';

// ─── Configuration ───────────────────────────────────────────────────────────
const urlParams   = new URLSearchParams(window.location.search);
const API_BASE    = urlParams.get('api') ||
                    (window.location.protocol.startsWith('http') && window.location.port === '8000' ? '' : 'http://localhost:8000');
const POLL_MS     = 2500;           // poll interval
const STALE_MS    = 10_000;         // mark stale if no success for 10 s

// ─── State ───────────────────────────────────────────────────────────────────
let lastSuccessTs   = null;
let lastAlertCount  = 0;
let staleTimer      = null;
let knownAlertIds   = new Set();    // track "ts+pod+rtm_id" to flash new rows

// ─── DOM helpers ─────────────────────────────────────────────────────────────
const $  = id => document.getElementById(id);
const qs = sel => document.querySelector(sel);

// ─── Utility ─────────────────────────────────────────────────────────────────
function fmtTs(unix) {
  if (!unix) return '—';
  const d = unix > 1e12 ? new Date(unix) : new Date(unix * 1000);
  return d.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function fmtIso(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function alertKey(a) {
  return `${a.ts}|${a.pod}|${a.rtm_id}`;
}

function priorityClass(p) {
  if (!p) return 'badge-muted';
  const l = p.toLowerCase();
  if (l === 'critical') return 'badge-red';
  if (l === 'error')    return 'badge-orange';
  if (l === 'warning')  return 'badge-yellow';
  return 'badge-muted';
}

function actionClass(action) {
  if (!action) return 'badge-muted';
  const a = action.toLowerCase();
  if (a === 'kill_pod')         return 'badge-red';
  if (a === 'isolate_network')  return 'badge-yellow';
  if (a === 'alert_only')       return 'badge-green';
  if (a === 'suppressed')       return 'badge-muted';
  return 'badge-muted';
}

// ─── Stale / Error state ──────────────────────────────────────────────────────
function setConnected() {
  lastSuccessTs = Date.now();
  $('status-dot').className   = 'status-dot';
  $('status-text').textContent = 'Connected';
  $('stale-banner').classList.remove('visible');
}

function setStale(errMsg) {
  $('status-dot').className   = 'status-dot stale';
  $('status-text').textContent = 'Stale';
  const banner = $('stale-banner');
  banner.classList.add('visible');
  $('stale-msg').textContent = errMsg
    ? `Controller unreachable: ${errMsg}`
    : `No successful poll in the last ${STALE_MS / 1000} s. Data may be outdated.`;
}

function setError(errMsg) {
  $('status-dot').className   = 'status-dot error';
  $('status-text').textContent = 'Offline';
  const banner = $('stale-banner');
  banner.classList.add('visible');
  $('stale-msg').textContent = `Controller unreachable — ${errMsg}`;
}

// ─── Config banner ────────────────────────────────────────────────────────────
function renderConfig(cfg) {
  const s = (cfg.strategy || '—').toLowerCase();
  const d = cfg.dry_run;
  const e = cfg.enforce_label_selector || '—';

  $('cfg-strategy').textContent = `STRATEGY=${s}`;
  const dryChip = $('cfg-dry-run');
  dryChip.textContent = `DRY_RUN=${d}`;
  dryChip.className   = `config-chip ${d ? 'dry-run-true' : 'dry-run-false'}`;
  $('cfg-enforce').textContent  = `ENFORCE=${e}`;
}

// ─── Pipeline strip ───────────────────────────────────────────────────────────
/**
 * Stages (0-indexed):
 *  0 Attack trigger     — always dim; user runs it manually
 *  1 Falco detection    — alert.ts present
 *  2 Falcosidekick fwd  — alert received (received_at present)
 *  3 Controller receive — same as above (combined with 2)
 *  4 Dedupe / decide    — decided_at present
 *  5 Safety gate        — decided_at present (gate evaluation done)
 *  6 Action             — action_taken present and not null/suppressed
 */
function renderPipeline(alerts) {
  const recent = alerts.slice(-20);  // look at last 20

  // Stage 1: any alert with a ts
  const s1 = recent.some(a => a.ts);
  // Stage 2+3: received_at
  const s2 = recent.some(a => a.received_at);
  // Stage 4: decided_at
  const s4 = recent.some(a => a.decided_at);
  // Stage 5: gate evaluated (decided_at present)
  const s5 = s4;
  // Stage 6: real action taken
  const s6 = recent.some(a => a.action_taken && a.action_taken !== 'suppressed');

  // gate blocked on most recent decided alert?
  const lastDecided = [...recent].reverse().find(a => a.decided_at);
  const gateBlocked = lastDecided && lastDecided.gate_blocked_reason;

  const steps = [
    { id: 'ps-attack',   active: false,                              warn: false, danger: false },
    { id: 'ps-falco',    active: s1,                                 warn: false, danger: false },
    { id: 'ps-sidekick', active: s2,                                 warn: false, danger: false },
    { id: 'ps-receive',  active: s2,                                 warn: false, danger: false },
    { id: 'ps-decide',   active: s4,                                 warn: false, danger: false },
    { id: 'ps-gate',     active: s5, warn: !!gateBlocked,           danger: false },
    { id: 'ps-action',   active: s6, warn: false,                   danger: s6 && lastDecided && lastDecided.action_taken === 'kill_pod' },
  ];

  for (const step of steps) {
    const el = $(step.id);
    if (!el) continue;
    el.classList.toggle('active', step.active);
    el.classList.toggle('warn',   step.active && step.warn);
    el.classList.toggle('danger', step.active && step.danger);
  }
}

// ─── Stats row ────────────────────────────────────────────────────────────────
function renderStats(alerts) {
  const total     = alerts.length;
  const actions   = alerts.filter(a => a.action_taken && a.action_taken !== 'suppressed' && a.action_taken !== null).length;
  const kills     = alerts.filter(a => a.action_taken === 'kill_pod').length;
  const suppressed= alerts.filter(a => a.dedupe_suppressed === true).length;

  $('stat-total').textContent     = total;
  $('stat-actions').textContent   = actions;
  $('stat-kills').textContent     = kills;
  $('stat-suppressed').textContent= suppressed;

  $('stat-kills').className = `stat-value ${kills > 0 ? 'red' : ''}`;
  $('stat-actions').className = `stat-value ${actions > 0 ? 'yellow' : 'green'}`;
}

// ─── Alert table ─────────────────────────────────────────────────────────────
function renderAlerts(alerts) {
  const tbody = $('alert-tbody');
  const toShow = [...alerts].reverse().slice(0, 50);

  if (toShow.length === 0) {
    tbody.innerHTML = `
      <tr><td colspan="10" class="table-empty">
        <span class="empty-icon">🔍</span>
        No RTM alerts received yet. Run an attack scenario to populate.
      </td></tr>`;
    return;
  }

  const rows = toShow.map(a => {
    const key  = alertKey(a);
    const isNew = !knownAlertIds.has(key);

    const rtmBadge      = `<span class="badge badge-rtm">${a.rtm_id || '—'}</span>`;
    const priBadge      = `<span class="badge ${priorityClass(a.priority)}">${a.priority || '—'}</span>`;
    const hintBadge     = `<span class="badge badge-muted">${a.response_hint || '—'}</span>`;
    const dedupeTxt     = a.dedupe_suppressed === null ? '—' :
                          a.dedupe_suppressed ? '<span class="badge badge-muted">suppressed</span>' :
                                               '<span class="badge badge-green">passed</span>';
    const dryBadge      = a.dry_run === null  ? '—' :
                          a.dry_run           ? '<span class="badge badge-yellow">dry</span>' :
                                               '<span class="badge badge-red">live</span>';
    const actionBadge   = a.action_taken
                          ? `<span class="badge action-badge ${actionClass(a.action_taken)}">${a.action_taken}</span>`
                          : '—';
    const gateTxt       = a.gate_blocked_reason
                          ? `<span class="badge badge-yellow" title="${a.gate_blocked_reason}">blocked</span>`
                          : (a.decided_at ? '<span class="badge badge-green">passed</span>' : '—');

    const podShort = a.pod ? a.pod.replace(/-[a-z0-9]{9,}$/, '-…') : '—';

    return `<tr class="${isNew ? 'new-row' : ''}" data-key="${key}">
      <td>${fmtIso(a.ts)}</td>
      <td>${rtmBadge}</td>
      <td title="${a.pod || ''}">${podShort}</td>
      <td>${priBadge}</td>
      <td>${hintBadge}</td>
      <td>${dedupeTxt}</td>
      <td>${dryBadge}</td>
      <td>${gateTxt}</td>
      <td>${actionBadge}</td>
      <td>${a.gate_blocked_reason ? `<span style="font-size:9px;color:var(--text-muted);max-width:120px;overflow:hidden;text-overflow:ellipsis;display:inline-block" title="${a.gate_blocked_reason}">${a.gate_blocked_reason}</span>` : '—'}</td>
    </tr>`;
  });

  tbody.innerHTML = rows.join('');

  // track seen
  toShow.forEach(a => knownAlertIds.add(alertKey(a)));
}

// ─── Pod grid ─────────────────────────────────────────────────────────────────
function renderPods(pods) {
  const container = $('pod-grid');
  if (!pods || pods.length === 0) {
    container.innerHTML = '<p style="color:var(--text-muted);font-size:13px;">No pods found.</p>';
    return;
  }

  const cards = pods.map(p => {
    const enforced   = p.rtm_enforce === 'true';
    const restricted = p.rtm_tier === 'restrict';
    const phase      = (p.phase || 'Unknown').toLowerCase();

    const labelPills = [];
    if (enforced)   labelPills.push('<span class="badge badge-green">rtm.enforce=true</span>');
    if (restricted) labelPills.push('<span class="badge badge-yellow">rtm.tier=restrict</span>');
    if (!enforced && !restricted) labelPills.push('<span class="badge badge-muted">no enforce label</span>');

    const restartTxt = p.restart_count > 0
      ? `<span style="color:var(--orange)">${p.restart_count} restart${p.restart_count !== 1 ? 's' : ''}</span>`
      : `${p.restart_count} restarts`;

    return `
      <div class="pod-card ${enforced ? 'enforced' : ''} ${restricted ? 'restricted' : ''}">
        <div class="pod-name" title="${p.name}">${p.name}</div>
        <div class="pod-labels">${labelPills.join('')}</div>
        <div class="pod-meta">
          <span class="pod-phase ${phase}">${phase}</span>
          <span style="font-family:var(--mono);font-size:10px">${restartTxt}</span>
        </div>
      </div>`;
  });

  container.innerHTML = cards.join('');
}

// ─── Polling ──────────────────────────────────────────────────────────────────
async function fetchJSON(path) {
  const r = await fetch(API_BASE + path, { cache: 'no-store' });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

async function poll() {
  try {
    const [alertsRes, podsRes, cfgRes] = await Promise.all([
      fetchJSON('/alerts/recent'),
      fetchJSON('/pods/status?namespace=shop'),
      fetchJSON('/config'),
    ]);

    setConnected();
    $('last-updated').textContent = 'Updated ' + new Date().toLocaleTimeString();

    const alerts = alertsRes.alerts || [];
    const pods   = podsRes.pods   || [];

    renderConfig(cfgRes);
    renderPipeline(alerts);
    renderStats(alerts);
    renderAlerts(alerts);
    renderPods(pods);

    lastAlertCount = alerts.length;

  } catch (err) {
    const ageMs = lastSuccessTs ? (Date.now() - lastSuccessTs) : Infinity;
    if (ageMs > STALE_MS) {
      setError(err.message);
    } else {
      setStale(err.message);
    }
    console.warn('RTM poll error:', err.message);
  }
}

// ─── Copy buttons ─────────────────────────────────────────────────────────────

// ─── Threat Injection Simulation ─────────────────────────────────────────────
// E1–E4 are active in the dashboard. E5–E8 are temporarily disabled.
// To re-enable any scenario: add to ENABLED_SCENARIOS and remove 'disabled' from index.html.
const ENABLED_SCENARIOS = new Set(['E1', 'E2', 'E3', 'E4']);
let isSimulationRunning = false;

function initThreatInjection() {
  const buttons = document.querySelectorAll('.threat-btn');
  buttons.forEach(btn => {
    btn.addEventListener('click', (e) => {
      if (btn.disabled) {
        e.preventDefault();
        return;
      }
      const scenario = btn.getAttribute('data-scenario');
      if (!scenario || !ENABLED_SCENARIOS.has(scenario)) {
        e.preventDefault();
        return;
      }
      triggerSimulation(scenario, btn);
    });
  });
}

function setButtonsDisabled(disabled) {
  document.querySelectorAll('.threat-btn').forEach(b => {
    const scenario = b.getAttribute('data-scenario');
    if (!ENABLED_SCENARIOS.has(scenario)) {
      // E5–E8 remain disabled at all times
      b.disabled = true;
    } else {
      b.disabled = disabled;
    }
  });
}

function setSimulationError(scenario, errorMsg, btn) {
  if (btn) {
    btn.classList.remove('loading', 'active-injecting');
  }
  setButtonsDisabled(false);
  isSimulationRunning = false;

  const card = $('simulation-feedback');
  if (card) card.className = 'simulation-feedback error';
  const dot = $('feedback-dot');
  if (dot) dot.className = 'feedback-status-dot error';
  const title = $('feedback-title');
  if (title) title.textContent = `Simulation Failed (${scenario})`;
  const body = $('feedback-body');
  if (body) {
    body.innerHTML = `<span style="color:var(--red);font-weight:500">Error:</span> ${errorMsg}`;
  }
  const stepExec = $('fb-step-exec');
  if (stepExec) stepExec.className = 'fb-step failed';
}

async function triggerSimulation(scenario, btn) {
  if (isSimulationRunning) return;
  if (!ENABLED_SCENARIOS.has(scenario)) return;
  isSimulationRunning = true;

  // 1. Disable all buttons, mark active button loading
  setButtonsDisabled(true);
  btn.classList.add('loading', 'active-injecting');

  // 2. Setup feedback UI
  const card = $('simulation-feedback');
  const dot = $('feedback-dot');
  const title = $('feedback-title');
  const simIdEl = $('feedback-sim-id');
  const body = $('feedback-body');
  const steps = $('feedback-steps');

  if (card) card.className = 'simulation-feedback running';
  if (dot) dot.className = 'feedback-status-dot running';
  if (steps) steps.style.display = 'flex';
  if (simIdEl) simIdEl.textContent = 'executing…';

  $('fb-step-exec').className = 'fb-step active';
  $('fb-step-detect').className = 'fb-step';
  $('fb-step-decision').className = 'fb-step';
  $('fb-step-gate').className = 'fb-step';

  const scenName = btn.querySelector('.threat-name')?.textContent || scenario;
  if (title) title.textContent = `Injecting ${scenario} (${scenName})…`;
  if (body) {
    body.innerHTML = `Executing controlled simulation command in test workload <code>shop/victim</code>…`;
  }

  // 3. Post to backend simulation API
  let simData;
  try {
    const res = await fetch(API_BASE + '/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario }),
    });

    if (!res.ok) {
      let detail = `Server responded with HTTP ${res.status}`;
      try {
        const errJson = await res.json();
        if (errJson.detail) detail = errJson.detail;
      } catch (_) {}
      setSimulationError(scenario, detail, btn);
      return;
    }

    simData = await res.json();
  } catch (err) {
    setSimulationError(scenario, `Network error: ${err.message}`, btn);
    return;
  }

  // 4. Simulation command executed in container
  $('fb-step-exec').className = 'fb-step done';
  if (simIdEl) simIdEl.textContent = simData.simulation_id || '';
  $('fb-step-detect').className = 'fb-step active';

  if (title) title.textContent = `Simulation Completed · Awaiting Falco Detection…`;
  if (body) {
    body.innerHTML = `Simulation command executed in <code>${simData.target?.pod || 'victim'}</code> (${simData.duration_s} s). Awaiting Falco kernel eBPF detection &amp; controller pipeline…`;
  }

  // 5. Correlate with real alert arriving via Falco -> Falcosidekick -> Controller pipeline
  await correlateAlert(simData, btn);
}

async function correlateAlert(simData, btn) {
  const maxWaitMs = 14000;
  const pollIntervalMs = 750;
  const startTime = Date.now();
  const expectedRules = simData.expected_rules || [];
  const targetPod = simData.target?.pod;
  const execTs = simData.executed_at || (startTime / 1000);

  let matchedAlert = null;

  while ((Date.now() - startTime) < maxWaitMs) {
    try {
      const res = await fetchJSON('/alerts/recent');
      const alerts = res.alerts || [];

      // Look for a real alert matching the victim workload and rule emitted at or after execution
      matchedAlert = alerts.find(a => {
        const alertTs = a.received_at || (a.ts ? new Date(a.ts).getTime() / 1000 : 0);
        const matchesPod = a.pod && (a.pod === targetPod || a.pod.includes('victim'));
        const matchesRule = expectedRules.includes(a.rtm_id);
        const isRecent = alertTs >= (execTs - 3.5);
        return matchesPod && matchesRule && isRecent;
      });

      if (matchedAlert) break;
    } catch (e) {
      console.warn('Correlation poll error:', e);
    }

    await new Promise(r => setTimeout(r, pollIntervalMs));
  }

  const card = $('simulation-feedback');
  const dot = $('feedback-dot');
  const title = $('feedback-title');
  const body = $('feedback-body');

  if (matchedAlert) {
    // 6. Threat successfully detected via real pipeline
    $('fb-step-detect').className = 'fb-step done';
    $('fb-step-decision').className = 'fb-step done';
    $('fb-step-gate').className = 'fb-step done';

    if (card) card.className = 'simulation-feedback success';
    if (dot) dot.className = 'feedback-status-dot success';

    const ruleBadge = `<span class="badge badge-rtm">${matchedAlert.rtm_id}</span>`;
    const priBadge  = `<span class="badge ${priorityClass(matchedAlert.priority)}">${matchedAlert.priority || '—'}</span>`;
    const actionBadge = matchedAlert.action_taken
      ? `<span class="badge action-badge ${actionClass(matchedAlert.action_taken)}">${matchedAlert.action_taken}</span>`
      : '—';

    let gateHtml;
    if (matchedAlert.gate_blocked_reason) {
      gateHtml = `<span class="badge badge-yellow">Blocked: ${matchedAlert.gate_blocked_reason}</span>`;
    } else if (matchedAlert.dry_run) {
      gateHtml = `<span class="badge badge-yellow">DRY_RUN=true (Enforcement Safety Guard Active)</span>`;
    } else {
      gateHtml = `<span class="badge badge-green">Enforcement Live</span>`;
    }

    const elapsedTotal = ((Date.now() - (execTs * 1000)) / 1000).toFixed(2);

    if (title) {
      title.innerHTML = `Threat Detected: ${matchedAlert.rtm_id} &middot; Decision Evaluated`;
    }

    if (body) {
      body.innerHTML = `
        <div style="margin-bottom:6px">
          <strong>Detection:</strong> ${ruleBadge} <code>${matchedAlert.rule || ''}</code> &middot; ${priBadge}
        </div>
        <div style="margin-bottom:6px">
          <strong>Decision Action:</strong> ${actionBadge} &nbsp;&middot;&nbsp; <strong>Safety Gate:</strong> ${gateHtml}
        </div>
        <div style="font-size:11px;color:var(--text-muted);font-family:var(--mono);margin-top:4px">
          Workload: ${matchedAlert.pod || targetPod} &middot; Exec: ${simData.duration_s}s &middot; End-to-end detection: ${elapsedTotal}s
        </div>
      `;
    }

    // Immediately trigger a full dashboard poll to update the live table and pipeline
    poll();

  } else {
    // 7. Bounded timeout reached without real detection alert
    $('fb-step-detect').className = 'fb-step failed';
    if (card) card.className = 'simulation-feedback error';
    if (dot) dot.className = 'feedback-status-dot error';

    if (title) title.textContent = `Detection Timeout (No Alert Received)`;
    if (body) {
      body.innerHTML = `
        Simulation command executed in <code>${targetPod || 'victim'}</code> (${simData.duration_s} s), but no matching alert (${expectedRules.join(', ')}) was received from the Falco &rarr; Controller pipeline within 14 s.
        <div style="margin-top:4px;font-size:11px;color:var(--text-muted)">
          Check that Falco daemonset and Falcosidekick pods are healthy.
        </div>
      `;
    }
  }

  // Cleanup button states
  setTimeout(() => {
    btn.classList.remove('loading', 'active-injecting');
    setButtonsDisabled(false);
    isSimulationRunning = false;
  }, 1000);
}

function initCopyButtons() {
  document.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const code = btn.previousElementSibling?.textContent?.trim();
      if (!code) return;
      navigator.clipboard.writeText(code).then(() => {
        btn.textContent = '✓ Copied';
        btn.classList.add('copied');
        setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 2000);
      });
    });
  });
}

// ─── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  // Initial render of empty states
  $('last-updated').textContent = 'Connecting…';
  initCopyButtons();
  initThreatInjection();
  initReset();

  // First poll immediately, then repeat
  poll();
  setInterval(poll, POLL_MS);
});


// ─── Toast notification system ────────────────────────────────────────────────
(function ensureToastContainer() {
  if (!document.getElementById('toast-container')) {
    const tc = document.createElement('div');
    tc.id = 'toast-container';
    document.body.appendChild(tc);
  }
})();

/**
 * Show a brief toast notification.
 * @param {'success'|'error'|'info'} type
 * @param {string} title  Bold heading text
 * @param {string} body   Supporting text (optional)
 * @param {number} durationMs  Auto-dismiss after this many ms (default 4000)
 */
function showToast(type, title, body = '', durationMs = 4000) {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    document.body.appendChild(container);
  }

  const icons = { success: '✅', error: '❌', info: 'ℹ️' };
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.setAttribute('role', 'status');
  toast.setAttribute('aria-live', 'polite');
  toast.innerHTML = `
    <span class="toast-icon" aria-hidden="true">${icons[type] || 'ℹ️'}</span>
    <span class="toast-msg">
      <strong>${escHtml(title)}</strong>
      ${body ? escHtml(body) : ''}
    </span>
    <button class="toast-close" aria-label="Dismiss notification" title="Dismiss">×</button>
  `;

  function dismiss() {
    toast.classList.add('toast-leaving');
    toast.addEventListener('animationend', () => toast.remove(), { once: true });
  }

  toast.querySelector('.toast-close').addEventListener('click', dismiss);
  container.appendChild(toast);

  if (durationMs > 0) {
    setTimeout(dismiss, durationMs);
  }
}

function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ─── Reset Test Results ────────────────────────────────────────────────────────

/**
 * The admin token is the default dev token shipped with the controller.
 * In a real deployment this would come from a server-side session or
 * environment-specific configuration — never hardcoded secrets.
 * The controller defaults to "rtm-reset-dev-token" when ADMIN_TOKEN is unset.
 */
const ADMIN_TOKEN = 'rtm-reset-dev-token';

let isResetting = false;

function buildConfirmModal() {
  const overlay = document.createElement('div');
  overlay.className = 'confirm-overlay hidden';
  overlay.id = 'reset-confirm-overlay';
  overlay.setAttribute('role', 'dialog');
  overlay.setAttribute('aria-modal', 'true');
  overlay.setAttribute('aria-labelledby', 'reset-dialog-title');

  overlay.innerHTML = `
    <div class="confirm-dialog">
      <h3 id="reset-dialog-title">⚠️ Reset Test Results?</h3>
      <p>This will immediately clear the following controller-side in-memory state:</p>
      <ul>
        <li>Alert ring buffer (all stored RTM alerts)</li>
        <li>Deduplication timestamps (per pod/rule)</li>
        <li>Pod event history (used for escalation decisions)</li>
        <li>Action-tracking state (isolate / kill already taken)</li>
      </ul>
      <div class="confirm-note">
        <strong>Note:</strong> This does <em>not</em> clear Falco's own kernel/log state,
        reverse previously executed Kubernetes actions, cancel running simulations,
        or change the strategy, dry-run setting, or enforcement selectors.
      </div>
      <div class="confirm-actions">
        <button class="confirm-cancel" id="reset-cancel-btn" type="button">Cancel</button>
        <button class="confirm-proceed" id="reset-proceed-btn" type="button">Yes, Reset</button>
      </div>
    </div>
  `;

  document.body.appendChild(overlay);

  // Close on overlay backdrop click
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) closeConfirmModal();
  });

  // Close on Escape
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !overlay.classList.contains('hidden')) {
      closeConfirmModal();
    }
  });

  document.getElementById('reset-cancel-btn').addEventListener('click', closeConfirmModal);
  document.getElementById('reset-proceed-btn').addEventListener('click', executeReset);

  return overlay;
}

function openConfirmModal() {
  let overlay = document.getElementById('reset-confirm-overlay');
  if (!overlay) overlay = buildConfirmModal();
  overlay.classList.remove('hidden');
  // Focus the cancel button by default (safer default for destructive dialogs)
  const cancelBtn = document.getElementById('reset-cancel-btn');
  if (cancelBtn) setTimeout(() => cancelBtn.focus(), 50);
}

function closeConfirmModal() {
  const overlay = document.getElementById('reset-confirm-overlay');
  if (overlay) overlay.classList.add('hidden');
}

async function executeReset() {
  if (isResetting) return;
  isResetting = true;
  closeConfirmModal();

  const btn = document.getElementById('reset-btn');
  if (btn) {
    btn.disabled = true;
    btn.classList.add('loading');
    btn.querySelector('.reset-btn-icon').textContent = '↺';
  }

  try {
    const res = await fetch(API_BASE + '/admin/reset-test-results', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-RTM-Admin-Token': ADMIN_TOKEN,
      },
    });

    if (!res.ok) {
      let detail = `HTTP ${res.status}`;
      try {
        const errJson = await res.json();
        if (errJson.detail) detail = errJson.detail;
      } catch (_) {}

      showToast('error', 'Reset Failed', detail, 6000);
      return;
    }

    const data = await res.json();

    // Clear client-side state only after backend confirms success
    knownAlertIds.clear();

    // Trigger an immediate dashboard refresh
    await poll();

    showToast('success', 'Test Results Reset', 'Alert history and decision engine state cleared.', 5000);
    console.info('[RTM] Reset complete:', data);

  } catch (err) {
    showToast('error', 'Reset Failed', `Network error: ${err.message}`, 6000);
  } finally {
    isResetting = false;
    if (btn) {
      btn.disabled = false;
      btn.classList.remove('loading');
      btn.querySelector('.reset-btn-icon').textContent = '↺';
    }
  }
}

function initReset() {
  const btn = document.getElementById('reset-btn');
  if (!btn) {
    console.warn('[RTM] Reset button #reset-btn not found in DOM.');
    return;
  }
  btn.addEventListener('click', () => {
    if (isResetting) return;
    openConfirmModal();
  });
}
