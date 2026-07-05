/**
 * app.js — CyberShield AI Mobile
 * Handles navigation, API calls, scan logic, charts, and state.
 * All sizes/colours match the Streamlit dashboard tokens.
 */

'use strict';

// ── Config ───────────────────────────────────────────────────────
const API_BASE = 'https://cyber-threat-api-4gms.onrender.com/api/v1';

// Colour tokens (match Streamlit exactly)
const C = {
  bg:      '#0B1120', card:    '#111827', sidebar: '#0F172A',
  border:  '#1E293B', primary: '#2563EB', success: '#22C55E',
  warn:    '#F59E0B', crit:    '#EF4444', info:    '#38BDF8',
  high:    '#F97316', text:    '#F8FAFC', muted:   '#CBD5E1',
  purple:  '#A78BFA',
};

const RISK_CLR = { critical:C.crit, high:C.high, medium:C.warn, low:C.success, info:C.info };
const RISK_BG  = { critical:'#2D1515', high:'#2D1A0E', medium:'#2D2710', low:'#0F2D1A', info:'#0F2133' };
const RISK_ICO = { critical:'🔴', high:'🟠', medium:'🟡', low:'🟢', info:'🔵' };

// ── State ─────────────────────────────────────────────────────────
const state = {
  scanDb: [],   // scan records
  charts: {},   // chart instances
};

// ── Init ─────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  checkApiHealth();
  renderPerfTable();
  renderPerfChart();
  updateDashboard();
});

// ── Navigation ────────────────────────────────────────────────────
function switchPage(name) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => {
    b.classList.remove('active');
    b.removeAttribute('aria-current');
  });
  const page = document.getElementById('page-' + name);
  const btn  = document.getElementById('navBtn-' + name);
  if (page) page.classList.add('active');
  if (btn)  { btn.classList.add('active'); btn.setAttribute('aria-current', 'page'); }
  if (name === 'dashboard') updateDashboard();
  if (name === 'timeline')  renderTimeline();
}

// ── Scan Tabs ─────────────────────────────────────────────────────
function switchTab(name, el) {
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.scan-tab').forEach(t => {
    t.classList.remove('active');
    t.setAttribute('aria-selected', 'false');
  });
  const content = document.getElementById('tab-' + name);
  if (content) content.classList.add('active');
  if (el) { el.classList.add('active'); el.setAttribute('aria-selected', 'true'); }
  document.getElementById('resultCard').classList.add('hidden');
}

// ── API Health ────────────────────────────────────────────────────
async function checkApiHealth() {
  const dot   = document.getElementById('apiDot');
  const label = document.getElementById('apiLabel');
  try {
    const res = await fetch('https://cyber-threat-api-4gms.onrender.com/health', { signal: AbortSignal.timeout(6000) });
    if (res.ok) {
      dot.classList.add('online');
      label.textContent = 'API Online';
    } else {
      label.textContent = 'API Error';
    }
  } catch {
    label.textContent = 'API Waking Up';
  }
}

// ── Scan ──────────────────────────────────────────────────────────
async function runScan(type) {
  const overlay = document.getElementById('loadingOverlay');
  const resultCard = document.getElementById('resultCard');
  overlay.classList.remove('hidden');
  resultCard.classList.add('hidden');

  try {
    const { endpoint, payload } = buildPayload(type);
    const t0 = Date.now();
    const res = await fetch(API_BASE + endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(20000),
    });
    const elapsed = Date.now() - t0;
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    saveScan(type, data, elapsed, payload);
    renderResult(data, elapsed, type);
    updateDashboard();
  } catch (err) {
    showError(err.message || 'API unreachable. Retry in ~30s.');
  } finally {
    overlay.classList.add('hidden');
  }
}

function buildPayload(type) {
  switch (type) {
    case 'phishing':
      return {
        endpoint: '/detect/phishing',
        payload: { email_text: document.getElementById('emailInput').value, model: 'ensemble' },
      };
    case 'url':
      return {
        endpoint: '/detect/url',
        payload: { url: document.getElementById('urlInput').value.trim() },
      };
    case 'login':
      return {
        endpoint: '/detect/login',
        payload: {
          username:             document.getElementById('loginUser').value,
          country:              document.getElementById('loginCountry').value.toUpperCase().slice(0,2),
          hour_of_day:          parseInt(document.getElementById('loginHour').value, 10),
          day_of_week:          new Date().getDay(),
          failed_attempts:      0,
          known_device:         document.getElementById('chkUnknownDev').checked ? 0 : 1,
          vpn_enabled:          document.getElementById('chkVpn').checked ? 1 : 0,
          new_location:         document.getElementById('chkNewLoc').checked ? 1 : 0,
          is_business_hours:    1,
          login_duration:       120.0,
          session_duration:     1800.0,
          ip_country_mismatch:  0,
          new_device:           document.getElementById('chkUnknownDev').checked ? 1 : 0,
          typing_speed_anomaly: 0.1,
          concurrent_sessions:  1,
        },
      };
    case 'network':
      return {
        endpoint: '/detect/network',
        payload: {
          features: {
            src_bytes:         parseFloat(document.getElementById('netSrcBytes').value) || 500,
            dst_bytes:         parseFloat(document.getElementById('netDstBytes').value) || 200,
            duration:          0,
            serror_rate:       parseFloat(document.getElementById('netSynErr').value) || 0,
            rerror_rate:       0,
            root_shell:        document.getElementById('chkRootShell').checked ? 1.0 : 0.0,
            num_failed_logins: 0,
            same_srv_rate:     0.9,
            dst_host_count:    1.0,
          },
        },
      };
    default:
      throw new Error('Unknown scan type');
  }
}

// ── Save scan record ──────────────────────────────────────────────
function saveScan(type, data, elapsedMs, payload) {
  const now = new Date();
  const labels = {
    phishing: `Email · ${data.is_threat ? 'PHISHING' : 'Legitimate'}`,
    url:      `URL · ${(payload.url || '').slice(0, 30)}`,
    login:    `Login · ${(payload.username || 'user').slice(0, 20)}`,
    network:  `Network · ${(payload.features?.src_bytes || 0).toLocaleString()}B`,
  };
  state.scanDb.unshift({
    id:          Math.random().toString(36).slice(2,10).toUpperCase(),
    scan_type:   type,
    label:       labels[type] || type,
    risk_level:  data.risk_level || 'info',
    probability: data.probability || 0,
    threat_score: Math.round((data.probability || 0) * 100),
    is_threat:   !!data.is_threat,
    confidence:  data.explanation?.confidence || 0,
    processing_ms: elapsedMs,
    model_name:  data.model_name || 'AI Engine',
    status:      data.is_threat ? 'THREAT' : 'SAFE',
    date:        now.toLocaleDateString(),
    time:        now.toLocaleTimeString(),
  });
}

// ── Render result card ────────────────────────────────────────────
function renderResult(data, elapsed, type) {
  const card      = document.getElementById('resultCard');
  const risk      = data.risk_level || 'info';
  const prob      = data.probability || 0;
  const isThreat  = !!data.is_threat;
  const score     = Math.round(prob * 100);
  const conf      = data.explanation?.confidence || 0;
  const reasoning = data.explanation?.reasoning || '';
  const color     = RISK_CLR[risk] || C.info;
  const bg        = RISK_BG[risk]  || '#0F2133';
  const ico       = RISK_ICO[risk] || '⚪';
  const verdict   = isThreat ? `⚠️ THREAT DETECTED` : `✅ SAFE`;
  const vc        = isThreat ? C.crit : C.success;

  card.style.background   = bg;
  card.style.borderColor  = color + '40';
  card.style.borderLeftColor = color;

  card.innerHTML = `
    <div class="result-verdict" style="color:${vc}">${verdict}</div>
    <div style="margin-bottom:14px">
      <span class="risk-pill" style="background:${bg};color:${color};border-color:${color}45">
        ${ico} ${risk.toUpperCase()}
      </span>
      <span style="color:${C.muted};font-size:11px;margin-left:10px">⏱ ${elapsed}ms · 🤖 ${data.model_name || 'AI Engine'}</span>
    </div>
    <div class="result-stat-grid">
      <div class="result-stat">
        <div class="result-stat-label">Probability</div>
        <div class="result-stat-val" style="color:${color}">${(prob*100).toFixed(1)}%</div>
      </div>
      <div class="result-stat">
        <div class="result-stat-label">Confidence</div>
        <div class="result-stat-val" style="color:${C.warn}">${(conf*100).toFixed(1)}%</div>
      </div>
      <div class="result-stat">
        <div class="result-stat-label">Score</div>
        <div class="result-stat-val" style="color:${color}">${score}/100</div>
      </div>
    </div>
    ${reasoning ? `
    <div class="result-reasoning">
      <div class="result-reasoning-label">AI Reasoning</div>
      <div class="result-reasoning-text">${reasoning}</div>
    </div>` : ''}
  `;
  card.classList.remove('hidden');
  card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function showError(msg) {
  const card = document.getElementById('resultCard');
  card.style.background     = '#2D1515';
  card.style.borderLeftColor = C.crit;
  card.style.borderColor     = C.crit + '40';
  card.innerHTML = `<div style="color:${C.crit};font-weight:700;font-size:0.95rem">🔴 ${msg}</div>
    <div style="color:${C.muted};font-size:13px;margin-top:6px">The free API may take ~30s to wake up. Try again.</div>`;
  card.classList.remove('hidden');
}

// ── Dashboard update ──────────────────────────────────────────────
function updateDashboard() {
  const db = state.scanDb;
  const hasScans = db.length > 0;

  // KPI values
  const total    = db.length;
  const threats  = db.filter(r => r.is_threat).length;
  const critical = db.filter(r => r.risk_level === 'critical').length;
  const avgConf  = hasScans ? db.reduce((s,r) => s + r.confidence, 0) / total : 0;
  const accuracy = hasScans ? ((total - threats) / total * 100) : 0;

  document.getElementById('kpi-total').textContent    = hasScans ? total    : 'N/A';
  document.getElementById('kpi-threats').textContent  = hasScans ? threats  : 'N/A';
  document.getElementById('kpi-critical').textContent = hasScans ? critical : 'N/A';
  document.getElementById('kpi-accuracy').textContent = hasScans ? accuracy.toFixed(1) + '%' : 'N/A';
  document.getElementById('kpi-conf').textContent     = hasScans ? (avgConf * 100).toFixed(0) + '%' : 'N/A';

  const subEl = document.getElementById('kpi-threats-sub');
  subEl.textContent = hasScans
    ? (threats ? `${((threats/total)*100).toFixed(0)}% of scans` : '0 threats found')
    : 'Waiting for first scan';

  document.getElementById('kpi-accuracy-sub').textContent = hasScans ? '' : 'Waiting for first scan';
  document.getElementById('kpi-conf-sub').textContent     = hasScans ? '' : 'Waiting for first scan';

  // Show/hide charts vs empty state
  const chartsSection  = document.getElementById('chartsSection');
  const emptyState     = document.getElementById('emptyState');
  const recentSection  = document.getElementById('recentAlertsSection');

  if (hasScans) {
    chartsSection.classList.remove('hidden');
    emptyState.classList.add('hidden');
    recentSection.classList.remove('hidden');
    renderTimelineChart();
    renderDistChart();
    renderRecentAlerts();
  } else {
    chartsSection.classList.add('hidden');
    emptyState.classList.remove('hidden');
    recentSection.classList.add('hidden');
  }
}

// ── Timeline chart (dashboard) ────────────────────────────────────
function renderTimelineChart() {
  const ctx = document.getElementById('timelineChart').getContext('2d');
  if (state.charts.timeline) state.charts.timeline.destroy();

  const db = state.scanDb.slice().reverse();
  const labels = db.map(r => r.time);
  const allScores = db.map(r => r.threat_score);

  state.charts.timeline = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label: 'Threat Score',
        data: allScores,
        borderColor: C.primary,
        backgroundColor: 'rgba(37,99,235,0.10)',
        fill: true,
        tension: 0.3,
        pointRadius: 3,
        pointBackgroundColor: C.primary,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: {
        legend: { labels: { color: C.text, font: { family: 'Inter', size: 11 } } },
        tooltip: { titleColor: C.text, bodyColor: C.muted, backgroundColor: C.card, borderColor: C.border, borderWidth: 1 },
      },
      scales: {
        x: { ticks: { color: C.muted, font: { size: 10 } }, grid: { color: C.border } },
        y: { min: 0, max: 100, ticks: { color: C.muted, font: { size: 10 } }, grid: { color: C.border } },
      },
    },
  });
}

// ── Distribution chart ────────────────────────────────────────────
function renderDistChart() {
  const ctx = document.getElementById('distChart').getContext('2d');
  if (state.charts.dist) state.charts.dist.destroy();

  const counts = {};
  state.scanDb.forEach(r => { counts[r.scan_type] = (counts[r.scan_type] || 0) + 1; });
  const labels = Object.keys(counts).map(k => k.charAt(0).toUpperCase() + k.slice(1));
  const values = Object.values(counts);
  const colors = [C.crit, C.high, C.warn, C.success, C.info, C.purple];

  state.charts.dist = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{ data: values, backgroundColor: colors.slice(0, labels.length), borderColor: C.bg, borderWidth: 2 }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: {
        legend: { position: 'bottom', labels: { color: C.text, font: { family: 'Inter', size: 11 }, padding: 12 } },
        tooltip: { titleColor: C.text, bodyColor: C.muted, backgroundColor: C.card, borderColor: C.border, borderWidth: 1 },
      },
    },
  });
}

// ── Recent alerts (dashboard) ─────────────────────────────────────
function renderRecentAlerts() {
  const el = document.getElementById('recentAlertsList');
  const recent = state.scanDb.slice(0, 5);
  el.innerHTML = recent.map(rec => {
    const color = RISK_CLR[rec.risk_level] || C.info;
    return `
      <div class="timeline-item" role="listitem">
        <div class="timeline-dot" style="background:${color}"></div>
        <div class="timeline-body">
          <div class="timeline-label">${rec.label}</div>
          <div class="timeline-meta">${rec.date} ${rec.time} · ${rec.scan_type.toUpperCase()} · ${rec.model_name}</div>
        </div>
        <div class="timeline-score" style="color:${color}">${rec.threat_score}</div>
      </div>`;
  }).join('');
}

// ── Full timeline ─────────────────────────────────────────────────
function renderTimeline() {
  const list  = document.getElementById('timelineList');
  const empty = document.getElementById('timelineEmpty');
  const db = state.scanDb;
  if (!db.length) {
    list.innerHTML = '';
    empty.classList.remove('hidden');
    return;
  }
  empty.classList.add('hidden');
  list.innerHTML = db.map(rec => {
    const color  = RISK_CLR[rec.risk_level] || C.info;
    const sColor = rec.is_threat ? C.crit : C.success;
    return `
      <div class="timeline-item" role="listitem">
        <div class="timeline-dot" style="background:${color}"></div>
        <div class="timeline-body">
          <div class="timeline-label">${rec.label}</div>
          <div class="timeline-meta">${rec.date} ${rec.time} · <span style="color:${sColor};font-weight:700">${rec.status}</span> · ${rec.processing_ms}ms</div>
        </div>
        <div>
          <span class="risk-pill" style="background:${RISK_BG[rec.risk_level]};color:${color};border-color:${color}45;font-size:10px">
            ${RISK_ICO[rec.risk_level]} ${rec.risk_level.toUpperCase()}
          </span>
        </div>
      </div>`;
  }).join('');
}

// ── Performance table ─────────────────────────────────────────────
const PERF_DATA = [
  { model:'DistilBERT', task:'Phishing', f1:0.9708, auc:0.9891 },
  { model:'BERT',       task:'Phishing', f1:0.9751, auc:0.9903 },
  { model:'Random Forest', task:'Phishing', f1:0.9338, auc:0.9712 },
  { model:'XGBoost',    task:'URL',      f1:0.9618, auc:0.9847 },
  { model:'Random Forest', task:'URL',   f1:0.9535, auc:0.9801 },
  { model:'Iso Forest', task:'Login',    f1:0.9101, auc:0.9421 },
  { model:'XGBoost',    task:'Login',    f1:0.9379, auc:0.9659 },
  { model:'XGBoost',    task:'Network',  f1:0.9809, auc:0.9967 },
  { model:'Iso Forest', task:'Network',  f1:0.9198, auc:0.9512 },
];

function renderPerfTable() {
  const tbody = document.getElementById('perfTableBody');
  tbody.innerHTML = PERF_DATA.map(r => {
    const f1Color  = r.f1  >= 0.97 ? C.success : r.f1  >= 0.95 ? C.warn : C.info;
    const aucColor = r.auc >= 0.98 ? C.success : r.auc >= 0.95 ? C.warn : C.info;
    return `<tr>
      <td>${r.model}</td>
      <td style="color:${C.info}">${r.task}</td>
      <td style="color:${f1Color};font-weight:700;font-family:'JetBrains Mono',monospace">${r.f1.toFixed(4)}</td>
      <td style="color:${aucColor};font-weight:700;font-family:'JetBrains Mono',monospace">${r.auc.toFixed(4)}</td>
    </tr>`;
  }).join('');
}

function renderPerfChart() {
  const ctx = document.getElementById('perfChart').getContext('2d');
  const labels = PERF_DATA.map(r => r.model + ' (' + r.task + ')');
  const f1vals = PERF_DATA.map(r => r.f1);
  const aucvals = PERF_DATA.map(r => r.auc);

  state.charts.perf = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [
        {
          label: 'F1 Score',
          data: f1vals,
          backgroundColor: C.primary + 'CC',
          borderRadius: 4,
        },
        {
          label: 'ROC-AUC',
          data: aucvals,
          backgroundColor: C.info + 'CC',
          borderRadius: 4,
        },
      ],
    },
    options: {
      indexAxis: 'y',
      responsive: true, maintainAspectRatio: false,
      plugins: {
        legend: { labels: { color: C.text, font: { family: 'Inter', size: 11 } } },
        tooltip: { titleColor: C.text, bodyColor: C.muted, backgroundColor: C.card, borderColor: C.border, borderWidth: 1 },
      },
      scales: {
        x: { min: 0.88, max: 1.0, ticks: { color: C.muted, font: { size: 10 } }, grid: { color: C.border } },
        y: { ticks: { color: C.text, font: { size: 9 } }, grid: { color: 'transparent' } },
      },
    },
  });
}
