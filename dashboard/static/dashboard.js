/** dashboard/static/dashboard.js
 * Tool 4 HITL Dashboard Logic
 * This file is used with dashboard/templates/index.html.
 * Responsibilities:
 *   1.  State management: single source of truth for all alerts + UI state
 *   2.  API layer: typed fetch wrappers for every app.py endpoint
 *   3.  Alert list render: virtualized-style diff to avoid full redraws
 *   4.  Detail panel: full alert detail with animated feature bars
 *   5.  Decision flow: approve/monitor/ignore with mitigation feedback
 *   6.  Live chart: rolling severity histogram (last 60 scans)
 *   7.  Notifications: new-alert badge flashing + optional audio ping
 *   8.  Keyboard nav: j/k to move, a/m/i to decide, r to refresh
 *   9.  Unblock form: manual rule removal without going to the CLI
 *  10.  Export: download current alert list as CSV
 * Usage:
 * index.html loads this file last, after DOM:
 * <script src="/static/dashboard.js" defer></script>
 */

'use strict';

// 1. Config
const CFG = {
  apiBase: '',  // same-origin; override to 'http://localhost:5000' if needed
  pollInterval: 5_000,  // ms between background refreshes
  chartMaxPoints: 60,  // rolling window for severity chart
  animBarDelay: 30,  // ms stagger between feature bar animations
  toastDuration: 6_000,  // ms before mitigation toast fades
  audioEnabled: false,  // toggled by operator via bell button
  newAlertSound: 440,  // Hz for Web Audio ping on new HIGH alerts
};

// 2. State
const State = {
  alerts: [],  // full list from /api/alerts, newest first
  currentId: null,  // alert_id currently shown in detail panel
  tab: 'all',  // 'all' | 'pending' | 'resolved'
  seenIds: new Set(),  // alert_ids rendered before - for new-alert detection
  pollTimer: null,
  chartData: { high: [], medium: [], low: [], labels: [] },
  audioCtx: null, // lazily created AudioContext
  unblockOpen: false,
};

// 3. DOM shortcuts
const $ = id => document.getElementById(id);

// Safe innerText setter, escapes HTML entities
function setText(id, val) {
  const el = $(id);
  if (el) el.textContent = val ?? '—';
}

// 4. Formatting helpers
function fmtBytes(n) {
  n = Number(n) || 0;
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(2) + ' MB';
  if (n >= 1_000) return (n / 1_000).toFixed(1) + ' KB';
  return n + ' B';
}

function fmtNum(n) {
  return Number(n).toLocaleString();
}

function fmtUptime(s) {
  s = Math.round(s);
  if (s < 60)   return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  return `${h}h ${m}m`;
}

function fmtAge(unixTs) {
  const d = Math.round(Date.now() / 1000 - unixTs);
  if (d < 5) return 'just now';
  if (d < 60) return `${d}s ago`;
  if (d < 3600) return `${Math.floor(d / 60)}m ago`;
  return `${Math.floor(d / 3600)}h ago`;
}

function fmtScore(n) {
  return Number(n).toFixed(4);
}

// Extract the "Detection: …" line from an explanation block
function extractPattern(explanation) {
  const m = (explanation || '').match(/^Detection:\s*(.+)$/m);
  return m ? m[1].trim() : 'Anomaly detected';
}

// 5. Severity / add colors
const SEV_COLORS = {
  high:   { fg: '#ef4444', bg: '#2d1414', border: '#ef4444' },
  medium: { fg: '#f59e0b', bg: '#2d2008', border: '#f59e0b' },
  low:    { fg: '#3b82f6', bg: '#0d1f3c', border: '#3b82f6' },
};

function sevColor(sev) { return (SEV_COLORS[sev] || SEV_COLORS.low).fg; }
function sevBg(sev) { return (SEV_COLORS[sev] || SEV_COLORS.low).bg; }

function confColor(pct) {
  if (pct >= 80) return '#ef4444';
  if (pct >= 55) return '#f59e0b';
  return '#3b82f6';
}

// Bar fill colour by |Z| magnitude
function zColor(absZ) {
  if (absZ >= 3) return '#ef4444';
  if (absZ >= 2) return '#f59e0b';
  return '#3b82f6';
}

// Decision pill style
function pillStyle(decision) {
  const m = {
    pending: 'background:#2a2030;color:#a78bfa',
    approved: 'background:#2d1414;color:#ef4444',
    monitor: 'background:#2d2008;color:#f59e0b',
    ignored: 'background:#222536;color:#7b7f9e',
  };
  return m[decision] || m.pending;
}

// 6. API layer
async function apiFetch(path, opts = {}) {
  const url = CFG.apiBase + path;
  const r = await fetch(url, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  });
  if (!r.ok) {
    const body = await r.json().catch(() => ({}));
    throw Object.assign(new Error(body.error || `HTTP ${r.status}`), { status: r.status });
  }
  return r.json();
}

const API = {
  health: () => apiFetch('/api/health'),
  alerts: (state='') => apiFetch(`/api/alerts${state ? '?state=' + state : ''}`),
  alert: id => apiFetch(`/api/alerts/${id}`),
  decide: body => apiFetch('/api/decide', { method: 'POST', body: JSON.stringify(body) }),
  scan: body => apiFetch('/api/scan', { method: 'POST', body: JSON.stringify(body || {}) }),
  stats: () => apiFetch('/api/stats'),
  mitLog: (n=100) => apiFetch(`/api/mitigation/log?lines=${n}`),
  verify: (dpid=1) => apiFetch(`/api/mitigation/verify?dpid=${dpid}`),
  unblock: body => apiFetch('/api/mitigation/unblock', { method: 'POST', body: JSON.stringify(body) }),
};

// 7. POLLING LOOP
async function pollAll() {
  await Promise.allSettled([refreshHealth(), refreshAlerts()]);
}

async function refreshHealth() {
  try {
    const d = await API.health();
    setServerOnline(true);
    setText('uptime-val', fmtUptime(d.uptime_s));
    setText('last-scan-val', d.last_scan ? fmtAge(d.last_scan) : 'never');
  } catch {
    setServerOnline(false);
  }
}

function setServerOnline(online) {
  const dot = $('server-status-dot');
  const text = $('server-status-text');
  if (!dot || !text) return;
  dot.className = online ? 'dot dot-green' : 'dot dot-red';
  text.textContent = online ? 'connected' : 'offline';
}

async function refreshAlerts() {
  try {
    const d = await API.alerts();
    const prev = State.seenIds.size;
    const newAlerts = (d.alerts || []).filter(a => !State.seenIds.has(a.alert_id));

    State.alerts = d.alerts || [];
    State.alerts.forEach(a => State.seenIds.add(a.alert_id));

    renderAlertList();
    renderStats();
    updateChartData();

    // Notify on genuinely new alerts
    if (prev > 0 && newAlerts.length > 0) {
      notifyNewAlerts(newAlerts);
    }

    // Refresh detail panel if the displayed alert was updated
    if (State.currentId) {
      const fresh = State.alerts.find(a => a.alert_id === State.currentId);
      if (fresh) renderDetail(fresh);
    }

  } catch {
    // Silently retain current list on transient failures
  }
}

// 8. Alert list render

function filteredAlerts() {
  if (State.tab === 'pending') return State.alerts.filter(a => a.decision === 'pending');
  if (State.tab === 'resolved') return State.alerts.filter(a => a.decision !== 'pending');
  return State.alerts;
}

function renderAlertList() {
  const list = filteredAlerts();
  const el   = $('alert-list');
  if (!el) return;

  // Tab badge counts
  const pending = State.alerts.filter(a => a.decision === 'pending').length;
  updateTabCounts(pending);

  if (list.length === 0) {
    el.innerHTML = `<div class="empty-state">${emptyStateMsg()}</div>`;
    return;
  }

  el.innerHTML = list.map((a, idx) => alertRowHTML(a, idx)).join('');
}

function emptyStateMsg() {
  if (State.tab === 'pending')  return 'No pending alerts — network looks clean.';
  if (State.tab === 'resolved') return 'No resolved alerts yet.';
  return 'No alerts yet. Click ⚡ Scan now to run detection.';
}

function alertRowHTML(a, idx) {
  const active = a.alert_id === State.currentId ? ' active' : '';
  const pattern = extractPattern(a.explanation);
  const color = sevColor(a.severity);
  const cColor = confColor(a.confidence_pct);
  const isNew = idx === 0 && State.tab !== 'resolved' ? ' new-alert' : '';

  return `<div class="alert-row${active}${isNew}"
               data-id="${esc(a.alert_id)}"
               onclick="Dashboard.selectAlert('${esc(a.alert_id)}')">
    <div class="sev-bar" style="background:${color}"></div>
    <div class="alert-row-body">
      <div class="alert-row-top">
        <span class="alert-id">#${esc(a.alert_id)}</span>
        <span class="alert-ts">${fmtAge(a.created_at)}</span>
      </div>
      <div class="alert-pattern">${esc(pattern)}</div>
      <div class="alert-sub">
        ${esc(a.src_ip)}:${a.src_port}
        <span class="flow-arrow">→</span>
        ${esc(a.dst_ip)}:${a.dst_port}
        &nbsp;·&nbsp;${esc((a.protocol || '').toUpperCase())}
      </div>
    </div>
    <div class="alert-row-right">
      <span class="conf-badge" style="color:${cColor};background:${cColor}18">
        ${a.confidence_pct.toFixed(0)}%
      </span>
      <span class="decision-pill" style="${pillStyle(a.decision)}">${a.decision}</span>
    </div>
  </div>`;
}

function updateTabCounts(pendingCount) {
  // Pending tab badge
  const pb = $('tab-pending-count');
  if (pb) {
    pb.textContent = pendingCount;
    pb.className = 'tab-count' + (pendingCount > 0 ? ' visible' : '');
  }
  // All tab badge
  const ab = $('tab-all-count');
  if (ab) {
    ab.textContent = State.alerts.length;
    ab.className = 'tab-count' + (State.alerts.length > 0 ? ' visible' : '');
  }
}

// 9. Detail Panel
async function selectAlert(id) {
  State.currentId = id;

  // Highlight in list immediately (optimistic)
  document.querySelectorAll('.alert-row').forEach(r => {
    r.classList.toggle('active', r.dataset.id === id);
  });

  try {
    const a = await API.alert(id);
    showDetailPanel(true);
    renderDetail(a);
  } catch (e) {
    console.error('[Dashboard] selectAlert:', e);
  }
}

function showDetailPanel(visible) {
  const placeholder = $('detail-placeholder');
  const view = $('detail-view');
  if (!placeholder || !view) return;
  placeholder.style.display = visible ? 'none' : 'flex';
  view.className = visible ? 'detail-view visible' : 'detail-view';
}

  // Header
function renderDetail(a) {
  const chip = $('d-sev-chip');
  if (chip) {
    chip.textContent = a.severity.toUpperCase();
    chip.className = `sev-chip chip-${a.severity}`;
  }
  setText('d-pattern', extractPattern(a.explanation));

  // Confidence ring
  const ring = $('d-conf-ring');
  const cNum = $('d-conf-num');
  if (ring && cNum) {
    const c = confColor(a.confidence_pct);
    ring.style.borderColor = c;
    cNum.style.color = c;
    cNum.textContent = a.confidence_pct.toFixed(0) + '%';
  }

  // Flow fields
  setText('d-src', `${a.src_ip}:${a.src_port}`);
  setText('d-dst', `${a.dst_ip}:${a.dst_port}`);
  setText('d-proto', (a.protocol || '—').toUpperCase());
  setText('d-dpid', a.dpid ? `s${a.dpid}  (dpid=${a.dpid})` : '—');
  setText('d-bytes', `${fmtBytes(a.bytes)}  (${fmtNum(a.bytes)} bytes)`);
  setText('d-packets', fmtNum(a.packets));
  setText('d-duration', `${Number(a.duration).toFixed(4)} s`);
  setText('d-score', fmtScore(a.anomaly_score));
  setText('d-rank', `#${a.anomaly_rank} of ${a.batch_size}`);
  setText('d-time', a.created_at_str || '—');

  // Alert ID in detail header (if element exists)
  setText('d-alert-id', `Alert #${a.alert_id}`);

  // Feature deviations
  renderDeviations(a.top_deviations || []);

  // Explanation
  const exEl = $('d-explanation');
  if (exEl) exEl.textContent = a.explanation || '—';

  // Recommendation
  renderRecommendation(a.recommendation || '');

  // Decision bar
  renderDecisionBar(a);

  //Unblock button
  const ubBtn = $('btn-unblock');
  if (ubBtn) {
    ubBtn.style.display = a.decision === 'approved' ? 'inline-flex' : 'none';
    ubBtn.onclick = () => openUnblockForm(a);
  }

  // Reset mitigation toast
  hideMitToast();
}

function renderDeviations(devs) {
  const body = $('d-devs-body');
  if (!body) return;

  if (!devs || devs.length === 0) {
    body.textContent = 'No feature breakdown available.';
    return;
  }

  const maxZ = Math.max(...devs.map(d => Math.abs(d.z_score)), 1);

  body.innerHTML = devs.map((d, i) => {
    const absZ = Math.abs(d.z_score);
    const pct = Math.min(100, (absZ / maxZ) * 100);
    const col = zColor(absZ);
    const sign = d.z_score >= 0 ? '+' : '';
    const mult = d.multiplier >= 2 ? ` · ${d.multiplier.toFixed(1)}× baseline` : '';

    return `<div class="dev-row" data-idx="${i}">
      <div class="dev-label">
        <span>${esc(d.label)}</span>
        <span class="z-tag">Z=${sign}${d.z_score.toFixed(2)}${mult}</span>
      </div>
      <div class="dev-bar-track">
        <div class="dev-bar-fill"
             style="width:0%;background:${col};transition:width .5s ease ${i * CFG.animBarDelay}ms">
        </div>
      </div>
      <div class="dev-vals">
        <span>observed: <b style="color:var(--text)">${fmtBytes(d.flow_value)}</b></span>
        <span>baseline: ${fmtBytes(d.baseline_mean)} ± ${fmtBytes(d.baseline_std)}</span>
      </div>
    </div>`;
  }).join('');

  // Animate bars in next frame so CSS transition fires
  requestAnimationFrame(() => {
    body.querySelectorAll('.dev-bar-fill').forEach((bar, i) => {
      const absZ = Math.abs(devs[i].z_score);
      const pct  = Math.min(100, (absZ / maxZ) * 100);
      bar.style.width = pct + '%';
    });
  });
}

function renderRecommendation(rec) {
  const el = $('d-rec-options');
  if (!el) return;

  const parts = rec.split(/\n\n/).filter(Boolean);
  el.innerHTML = parts.map(p => {
    const cls = p.startsWith('⛔') ? 'opt-block'  :
                p.startsWith('👁') ? 'opt-monitor' : 'opt-ignore';
    return `<div class="rec-option ${cls}">${esc(p)}</div>`;
  }).join('');
}

function renderDecisionBar(a) {
  const decided = a.decision !== 'pending';
  const bar = $('decision-bar');
  if (bar) bar.className = 'decision-bar' + (decided ? ' decided' : '');

  const label = $('dec-label');
  if (label) {
    label.textContent = decided
      ? `Decision: ${a.decision.toUpperCase()}${a.decided_at_str ? '  ·  ' + a.decided_at_str : ''}`
      : 'Choose an action for this alert:';
  }

  ['btn-approve', 'btn-monitor', 'btn-ignore'].forEach(id => {
    const btn = $(id);
    if (btn) btn.disabled = decided;
  });
}

// 10. Decision Submission
async function decide(decision) {
  if (!State.currentId) return;

  // Disable buttons optimistically
  setDecisionButtons(true, 'Submitting…');

  try {
    const resp = await API.decide({
      alert_id: State.currentId,
      decision,
      decided_by: 'operator',
    });

    if (resp.alert) renderDetail(resp.alert);

    // Refresh list
    await refreshAlerts();

    // Show mitigation feedback
    showMitToast(decision, resp.mitigation);

  } catch (e) {
    setDecisionButtons(false, `Error: ${e.message}`);
  }
}

function setDecisionButtons(disabled, labelText) {
  ['btn-approve', 'btn-monitor', 'btn-ignore'].forEach(id => {
    const btn = $(id);
    if (btn) btn.disabled = disabled;
  });
  const label = $('dec-label');
  if (label && labelText) label.textContent = labelText;
}

function showMitToast(decision, mitigation) {
  const toast    = $('mit-toast');
  const toastTxt = $('mit-toast-text');
  if (!toast || !toastTxt) return;

  let text = '';
  let cls = 'mit-toast visible';

  if (decision === 'approved' && mitigation) {
    const ok = mitigation.status === 'success';
    cls  += ok ? '' : ' failed';
    text  = ok
      ? `🟢 DROP rule installed on s${mitigation.dpid} via ${mitigation.method}` +
        `  (cookie ${mitigation.rule_cookie})`
      : `🔴 Mitigation failed: ${mitigation.error || 'unknown error'}`;
  } else if (decision === 'monitor') {
    text = '👁 Alert flagged for monitoring — no SDN rule installed.';
  } else if (decision === 'ignored') {
    text = '✕ Alert dismissed as false positive.';
  } else {
    text = 'Decision recorded.';
  }

  toast.className = cls;
  toast.style.display = 'flex';
  toastTxt.textContent = text;

  // Auto-hide after CFG.toastDuration
  clearTimeout(toast._timer);
  toast._timer = setTimeout(hideMitToast, CFG.toastDuration);
}

function hideMitToast() {
  const toast = $('mit-toast');
  if (!toast) return;
  toast.className = 'mit-toast';
  toast.style.display = 'none';
  clearTimeout(toast._timer);
}

// 11. Stats Bar
function renderStats() {
  const a = State.alerts;
  setText('s-total', a.length);
  setText('s-pending', a.filter(x => x.decision === 'pending').length);
  setText('s-approved', a.filter(x => x.decision === 'approved').length);
  setText('s-monitor', a.filter(x => x.decision === 'monitor').length);
  setText('s-ignored', a.filter(x => x.decision === 'ignored').length);

  setText('count-high', a.filter(x => x.severity === 'high').length);
  setText('count-med', a.filter(x => x.severity === 'medium').length);
  setText('count-low', a.filter(x => x.severity === 'low').length);
}

// 12. Sevirity Chart (canvas sparkline, no library)
function updateChartData() {
  const a = State.alerts;
  const cd = State.chartData;

  cd.high.push(a.filter(x => x.severity === 'high').length);
  cd.medium.push(a.filter(x => x.severity === 'medium').length);
  cd.low.push(a.filter(x => x.severity === 'low').length);
  cd.labels.push(new Date().toLocaleTimeString());

  // Trim to rolling window
  const max = CFG.chartMaxPoints;
  if (cd.high.length > max) {
    cd.high.splice(0, cd.high.length - max);
    cd.medium.splice(0, cd.medium.length - max);
    cd.low.splice(0, cd.low.length - max);
    cd.labels.splice(0, cd.labels.length - max);
  }

  drawChart();
}

function drawChart() {
  const canvas = $('severity-chart');
  if (!canvas) return;

  const ctx = canvas.getContext('2d');
  const W = canvas.width;
  const H = canvas.height;
  const cd = State.chartData;
  const n = cd.high.length;

  ctx.clearRect(0, 0, W, H);

  if (n < 2) return;

  const maxVal = Math.max(...cd.high.map((h, i) => h + cd.medium[i] + cd.low[i]), 1);
  const padL = 4, padR = 4, padT = 6, padB = 4;
  const iW = W - padL - padR;
  const iH = H - padT - padB;

  function xOf(i) { return padL + (i / (n - 1)) * iW; }
  function yOf(v) { return padT + iH - (v / maxVal) * iH; }

  // Draw stacked area lines: low (bottom), medium, high (top)
  // We'll draw them as simple polylines for clarity — stacked means
  // each line's Y is total from 0, so they don't overlap visually.

  const series = [
    { data: cd.low, color: '#3b82f6' },
    { data: cd.medium, color: '#f59e0b' },
    { data: cd.high, color: '#ef4444' },
  ];

  series.forEach(({ data, color }) => {
    ctx.beginPath();
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.5;
    ctx.lineJoin = 'round';
    data.forEach((v, i) => {
      i === 0 ? ctx.moveTo(xOf(i), yOf(v)) : ctx.lineTo(xOf(i), yOf(v));
    });
    ctx.stroke();

    // Subtle fill below line
    ctx.lineTo(xOf(n - 1), padT + iH);
    ctx.lineTo(padL, padT + iH);
    ctx.closePath();
    ctx.fillStyle = color + '22';
    ctx.fill();
  });

  // Latest value dots
  series.forEach(({ data, color }) => {
    const last = data[n - 1];
    ctx.beginPath();
    ctx.arc(xOf(n - 1), yOf(last), 3, 0, Math.PI * 2);
    ctx.fillStyle = color;
    ctx.fill();
  });
}

// 13. Scan trigger
async function triggerScan() {
  const btn = $('scan-btn');
  if (btn) { btn.disabled = true; btn.textContent = '⏳ Scanning…'; }

  try {
    const d = await API.scan();
    if (btn) btn.textContent = `⚡ +${d.new_alerts} new`;
    await refreshAlerts();
  } catch (e) {
    if (btn) btn.textContent = '⚡ Scan now';
    console.warn('[Dashboard] Scan failed:', e.message);
  } finally {
    setTimeout(() => {
      if (btn) { btn.textContent = '⚡ Scan now'; btn.disabled = false; }
    }, 3000);
  }
}

// 14. Verify Rules Modal
async function verifyRules(dpid = 1) {
  const ov = $('verify-overlay');
  if (!ov) return;
  ov.style.display = 'flex';

  const out = $('verify-output');
  if (out) out.textContent = `Running ovs-ofctl dump-flows s${dpid} …`;

  try {
    const d = await API.verify(dpid);
    if (out) {
      // Colour-highlight the two cookies for clarity
      const raw = d.rules || '(no HITL rules found)';
      out.innerHTML = raw
        .split('\n')
        .map(line => {
          if (line.includes('feedfacecafe0004'))
            return `<span style="color:#22c55e">${esc(line)}</span>`;
          if (line.includes('deadbeefcafe0001'))
            return `<span style="color:#ef4444">${esc(line)}</span>`;
          return esc(line);
        })
        .join('\n');
    }
  } catch (e) {
    if (out) out.textContent = `Error: ${e.message}`;
  }
}

function closeVerify() {
  const ov = $('verify-overlay');
  if (ov) ov.style.display = 'none';
}

// 15. Mitigation Log
async function openMitLog() {
  const ov = $('log-overlay');
  if (!ov) return;
  ov.style.display = 'flex';

  const out = $('log-output');
  if (out) out.textContent = 'Loading…';

  try {
    const d = await API.mitLog(100);
    if (out) {
      const lines = d.log || [];
      out.textContent = lines.length > 0
        ? lines.join('\n')
        : 'No mitigation actions recorded yet.';
    }
  } catch (e) {
    if (out) out.textContent = `Error: ${e.message}`;
  }
}

function closeMitLog() {
  const ov = $('log-overlay');
  if (ov) ov.style.display = 'none';
}

// 16. Unblock Form
function openUnblockForm(alert) {
  // Populate the unblock modal with the alert's flow details
  const ov = $('unblock-overlay');
  if (!ov) return;

  const srcEl = $('ub-src-ip');
  const portEl = $('ub-dst-port');
  const protoEl = $('ub-protocol');
  const dpidEl = $('ub-dpid');
  const aidEl = $('ub-alert-id');

  if (srcEl) srcEl.value = alert.src_ip || '';
  if (portEl) portEl.value = alert.dst_port || 0;
  if (protoEl) protoEl.value = alert.protocol || 'tcp';
  if (dpidEl) dpidEl.value = alert.dpid || 1;
  if (aidEl) aidEl.value = alert.alert_id || '';

  ov.style.display = 'flex';
}

function closeUnblockForm() {
  const ov = $('unblock-overlay');
  if (ov) ov.style.display = 'none';
  setText('ub-result', '');
}

async function submitUnblock() {
  const srcIp = ($('ub-src-ip') || {}).value || '';
  const dstPort = parseInt(($('ub-dst-port') || {}).value || '0', 10);
  const proto = ($('ub-protocol') || {}).value || 'tcp';
  const dpid = parseInt(($('ub-dpid') || {}).value || '1', 10);
  const alertId = ($('ub-alert-id') || {}).value || 'manual';

  if (!srcIp) { setText('ub-result', '⚠ src_ip is required.'); return; }

  setText('ub-result', 'Sending unblock request…');

  try {
    const d = await API.unblock({ src_ip: srcIp, dst_port: dstPort, protocol: proto, dpid, alert_id: alertId });
    const ok = d.status === 'success';
    setText('ub-result', ok
      ? `🟢 Rule removed via ${d.method}`
      : `🔴 Unblock failed: ${d.error || 'unknown'}`);
    if (ok) await refreshAlerts();
  } catch (e) {
    setText('ub-result', `✗ Error: ${e.message}`);
  }
}

// 17. CSV Export
function exportCSV() {
  const alerts = filteredAlerts();
  if (alerts.length === 0) { alert('No alerts to export.'); return; }

  const cols = [
    'alert_id', 'created_at_str', 'severity', 'confidence_pct',
    'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol',
    'bytes', 'packets', 'duration', 'anomaly_score', 'anomaly_rank',
    'decision', 'decided_at_str',
  ];

  const header = cols.join(',');
  const rows = alerts.map(a =>
    cols.map(c => {
      const v = a[c] ?? '';
      return typeof v === 'string' && v.includes(',') ? `"${v}"` : v;
    }).join(',')
  );

  const csv = [header, ...rows].join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `hitl-alerts-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

// 18. Keyboard Nav
function initKeyboard() {
  document.addEventListener('keydown', e => {
    // Ignore keypresses inside input fields
    if (['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName)) return;

    const list = filteredAlerts();
    const curIdx = list.findIndex(a => a.alert_id === State.currentId);

    switch (e.key) {
      case 'j': case 'ArrowDown': {
        const next = list[Math.min(curIdx + 1, list.length - 1)];
        if (next) selectAlert(next.alert_id);
        e.preventDefault();
        break;
      }
      case 'k': case 'ArrowUp': {
        const prev = list[Math.max(curIdx - 1, 0)];
        if (prev) selectAlert(prev.alert_id);
        e.preventDefault();
        break;
      }
      case 'a':
        if (State.currentId) decide('approved');
        break;
      case 'm':
        if (State.currentId) decide('monitor');
        break;
      case 'i':
        if (State.currentId) decide('ignored');
        break;
      case 'r':
        triggerScan();
        break;
      case 'Escape':
        closeVerify(); closeMitLog(); closeUnblockForm();
        break;
      case '?':
        toggleKeyboardHelp();
        break;
    }
  });
}

function toggleKeyboardHelp() {
  const el = $('keyboard-help');
  if (!el) return;
  el.style.display = el.style.display === 'flex' ? 'none' : 'flex';
}

// 19. Tab switching
function setTab(tab, el) {
  State.tab = tab;
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  if (el) el.classList.add('active');
  renderAlertList();
}

// 20. New Alert Notification
function notifyNewAlerts(newAlerts) {
  const highCount = newAlerts.filter(a => a.severity === 'high').length;

  // Page title flash
  const orig = document.title;
  let flashing = true;
  const iv = setInterval(() => {
    document.title = flashing ? `(${newAlerts.length} new) ${orig}` : orig;
    flashing = !flashing;
  }, 800);
  setTimeout(() => { clearInterval(iv); document.title = orig; }, 8000);

  // Audio ping for HIGH alerts
  if (CFG.audioEnabled && highCount > 0) {
    playPing();
  }

  // Browser notification (if permission granted)
  if (Notification.permission === 'granted' && highCount > 0) {
    new Notification('SDN HITL Alert', {
      body: `${highCount} HIGH-severity alert${highCount > 1 ? 's' : ''} detected`,
      icon: '/static/favicon.ico',
    });
  }
}

function playPing() {
  try {
    if (!State.audioCtx) State.audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const ctx = State.audioCtx;
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.frequency.value = CFG.newAlertSound;
    osc.type = 'sine';
    gain.gain.setValueAtTime(0.15, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.4);
    osc.start(ctx.currentTime);
    osc.stop(ctx.currentTime + 0.4);
  } catch { /* audio not available */ }
}

function toggleAudio() {
  CFG.audioEnabled = !CFG.audioEnabled;
  const btn = $('btn-audio');
  if (btn) btn.textContent = CFG.audioEnabled ? '🔔 Sound on' : '🔕 Sound off';
  // Request browser notification permission on first enable
  if (CFG.audioEnabled && Notification.permission === 'default') {
    Notification.requestPermission();
  }
}

// 21. Close overlays on background check
function initOverlayDismiss() {
  ['verify-overlay', 'log-overlay', 'unblock-overlay', 'keyboard-help'].forEach(id => {
    const el = $(id);
    if (!el) return;
    el.addEventListener('click', e => {
      if (e.target === el) el.style.display = 'none';
    });
  });
}

// 22. HTML escape
function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// 23. Public Interface, called from index.html onclick attributes
// index.html uses onclick="Dashboard.selectAlert(...)" etc.
// Expose all public functions under a single namespace to avoid globals.
window.Dashboard = {
  selectAlert,
  decide,
  triggerScan,
  verifyRules,
  closeVerify,
  openMitLog,
  closeMitLog,
  openUnblockForm,
  closeUnblockForm,
  submitUnblock,
  exportCSV,
  setTab,
  toggleAudio,
  toggleKeyboardHelp,
};

// Also expose the functions index.html calls directly (no namespace prefix)
// These match the onclick="..." attributes written in index.html
window.selectAlert = selectAlert;
window.decide = decide;
window.triggerScan = triggerScan;
window.verifyRules = verifyRules;
window.closeOverlay = id => { const el = $(id); if (el) el.style.display = 'none'; };
window.openMitLog = openMitLog;
window.exportCSV = exportCSV;
window.setTab = setTab;
window.toggleAudio = toggleAudio;
window.toggleKeyboardHelp = toggleKeyboardHelp;

// 24. Boot function
function boot() {
  initKeyboard();
  initOverlayDismiss();

  // Initial data fetch
  pollAll();

  // Start polling loop
  State.pollTimer = setInterval(pollAll, CFG.pollInterval);

  // Initial chart draw (blank but creates canvas context)
  drawChart();

  console.info(
    '[HITL Dashboard] Tool 4 running. ' +
    'Keyboard: j/k navigate · a approve · m monitor · i ignore · r scan · ? help'
  );
}

// Run last after DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', boot);
} else {
  boot();
}
