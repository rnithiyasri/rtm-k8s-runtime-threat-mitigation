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

  // First poll immediately, then repeat
  poll();
  setInterval(poll, POLL_MS);
});
