/**
 * ============================================================================
 * File: dashboard/static/js/app.js
 * Project: ZenGuard Zero Trust SIEM — Phase 6: Frontend Logic
 *
 * Description:
 *   All client-side logic for the ZenGuard SIEM dashboard. Responsibilities:
 *     1. Polling /api/events every 5 seconds with a full-refresh fallback
 *        every 30 seconds to ensure stale views never persist.
 *     2. Rendering events into the live events table with animations.
 *     3. Updating all 5 KPI cards from aggregated stats.
 *     4. Driving the Chart.js donut chart (severity distribution).
 *     5. Driving the Chart.js line chart (timeline sparkline).
 *     6. Populating the event detail modal with dataset info + field breakdown.
 *
 * Architecture:
 *   Vanilla JS — no framework, no build step, directly served by Flask.
 * ============================================================================
 */

"use strict";

// =============================================================================
// GLOBALS & STATE
// =============================================================================

const API_BASE           = "";        // same origin (Flask)
const POLL_INTERVAL_MS   = 5000;      // incremental poll every 5s
const FULL_REFRESH_MS    = 30000;     // full table refresh every 30s
const MAX_TABLE_ROWS     = 100;

// Incremental polling cursor
let lastSeen             = null;
let pollingTimer         = null;
let fullRefreshTimer     = null;

// Charts
let donutChart           = null;
let timelineChart        = null;

// Client-side dedup guard
let seenEventIds         = new Set();

// Track unique dataset sources seen this session
let activeDatasetsSet    = new Set();

// Timeline: 30 slots × 5s = 150-second rolling window
const TIMELINE_SLOTS     = 30;
let timelineData         = new Array(TIMELINE_SLOTS).fill(0);
let timelineLabels       = new Array(TIMELINE_SLOTS).fill("");

// Poll health
let consecutiveErrors    = 0;
let lastSuccessfulPoll   = null;


// =============================================================================
// DATASET METADATA
// Maps dataset keys used in the replayer to human-readable labels
// =============================================================================

const DATASET_META = {
  "cic":       { label: "CIC-IDS-2017", color: "#3b82f6",  icon: "bi-database-fill" },
  "unsw":      { label: "UNSW-NB15",    color: "#8b5cf6",  icon: "bi-database-fill" },
  "synthetic": { label: "Synthetic",    color: "#06b6d4",  icon: "bi-cpu-fill"       },
  "unknown":   { label: "Unknown",      color: "#64748b",  icon: "bi-question-circle" },
};

function getDatasetMeta(key) {
  const k = (key || "unknown").toLowerCase();
  return DATASET_META[k] || DATASET_META["unknown"];
}

function buildDatasetBadge(datasetKey) {
  const meta = getDatasetMeta(datasetKey);
  return `<span style="
      display:inline-flex; align-items:center; gap:4px;
      padding:2px 7px;
      background:${meta.color}18;
      border:1px solid ${meta.color}40;
      color:${meta.color};
      border-radius:4px;
      font-size:0.65rem;
      font-weight:600;
      white-space:nowrap;
    ">
    <i class="bi ${meta.icon}"></i>
    ${meta.label}
  </span>`;
}


// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

function formatTime(isoString) {
  if (!isoString) return "—";
  try {
    const d = new Date(isoString);
    return d.toLocaleTimeString([], { hour12: false,
      hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch { return isoString; }
}

function formatDateTime(isoString) {
  if (!isoString) return "—";
  try {
    const d = new Date(isoString);
    return d.toLocaleString([], {
      year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
      hour12: false
    });
  } catch { return isoString; }
}

function severityColor(sev) {
  const map = {
    critical: "#ef4444",
    high:     "#f97316",
    medium:   "#eab308",
    low:      "#22c55e",
    unknown:  "#64748b",
  };
  return map[(sev || "unknown").toLowerCase()] || map.unknown;
}

function buildRiskScoreCell(score) {
  const s = parseFloat(score) || 0;
  let color;
  if (s >= 70) color = "#ef4444";
  else if (s >= 40) color = "#f97316";
  else color = "#22c55e";

  return `
    <div class="risk-score-cell">
      <div class="risk-score-bar">
        <div class="risk-score-fill" style="width:${s}%; background:${color};"></div>
      </div>
      <span class="risk-score-num" style="color:${color};">${s}</span>
    </div>`;
}


// =============================================================================
// TABLE RENDERING
// =============================================================================

/**
 * Insert a single event as a new <tr> at the top of the events table.
 * Each row now shows: ID | TIME | USER | DEVICE/IP | EVENT TYPE |
 *                     SEVERITY | RISK SCORE | DATASET | DETAIL
 */
function prependEventRow(event) {
  const tbody = document.getElementById("events-tbody");

  // Remove placeholder row if present
  const emptyRow = tbody.querySelector("#events-empty");
  if (emptyRow) emptyRow.remove();

  const tr = document.createElement("tr");
  tr.classList.add("new-row");
  tr.dataset.eventId = event.id;

  const sev       = (event.severity || "unknown").toLowerCase();
  const eventType = event.event_type || "unknown";
  const row_src   = event.src_ip    || "—";
  const userId    = event.user_id   || "—";
  const device    = event.endpoint_id
    ? `${event.endpoint_id}<br><span class="td-mono" style="color:var(--text-muted)">${row_src}</span>`
    : row_src;

  // Parse raw_json to get dataset
  let datasetKey = "unknown";
  try {
    const raw = event.raw_json ? JSON.parse(event.raw_json) : {};
    datasetKey = raw.dataset || event.log_source || "unknown";
  } catch {}

  // Track active datasets for KPI card
  activeDatasetsSet.add(datasetKey);

  tr.innerHTML = `
    <td class="td-event-id" title="${event.id}">${event.id ? event.id.substring(0,12) + "…" : "—"}</td>
    <td class="td-mono">${formatTime(event.received_at)}</td>
    <td><span style="color:var(--accent-cyan);">${userId}</span></td>
    <td>${device}</td>
    <td><span class="badge-type">${eventType.replace(/_/g, " ")}</span></td>
    <td><span class="badge-sev ${sev}">
          <i class="bi bi-circle-fill" style="font-size:0.5em;"></i>${sev}
        </span></td>
    <td>${buildRiskScoreCell(event.risk_score)}</td>
    <td>${buildDatasetBadge(datasetKey)}</td>
    <td>
      <button class="action-btn detail-btn"
              data-detail-id="${event.id}"
              style="color:var(--accent-blue); border-color:rgba(59,130,246,0.3);">
        <i class="bi bi-search"></i> Detail
      </button>
    </td>`;

  tbody.insertBefore(tr, tbody.firstChild);

  // Prune overflow rows from the bottom
  const rows = tbody.querySelectorAll("tr");
  if (rows.length > MAX_TABLE_ROWS) {
    for (let i = MAX_TABLE_ROWS; i < rows.length; i++) rows[i].remove();
  }
}

function updateTableCount() {
  const count = document.querySelectorAll("#events-tbody tr:not(#events-empty)").length;
  document.getElementById("table-count").textContent = count;
}


// =============================================================================
// KPI CARD UPDATES
// =============================================================================

function animateCounter(elementId, targetValue) {
  const el = document.getElementById(elementId);
  if (!el) return;
  const start   = parseInt(el.textContent.replace(/[^0-9]/g, "")) || 0;
  const delta   = targetValue - start;
  const steps   = 20;
  const stepVal = delta / steps;
  let curr = start;
  let count = 0;

  const timer = setInterval(() => {
    curr += stepVal;
    count++;
    el.textContent = Math.round(curr);
    if (count >= steps) {
      el.textContent = targetValue;
      clearInterval(timer);
    }
  }, 30);
}

function updateKPICards(stats, byType) {
  const bySev = stats.by_severity || {};
  animateCounter("kpi-total",        stats.total    || 0);
  animateCounter("kpi-high-risk",    stats.high_risk || 0);
  animateCounter("kpi-critical",     bySev.critical || 0);
  animateCounter("kpi-failed-logins",(byType || {}).failed_logins || 0);
  // Active dataset sources KPI
  animateCounter("kpi-datasets", activeDatasetsSet.size);
}


// =============================================================================
// CHART.JS — SEVERITY DONUT CHART
// =============================================================================

const SEV_ORDER  = ["critical", "high", "medium", "low", "unknown"];
const SEV_COLORS = {
  critical: "#ef4444",
  high:     "#f97316",
  medium:   "#eab308",
  low:      "#22c55e",
  unknown:  "#64748b",
};

function updateDonutChart(bySeverity) {
  const labels = SEV_ORDER.filter(s => bySeverity[s] > 0);
  const values = labels.map(s => bySeverity[s]);
  const colors = labels.map(s => SEV_COLORS[s]);

  if (!donutChart) {
    const ctx = document.getElementById("riskDonutChart").getContext("2d");
    donutChart = new Chart(ctx, {
      type: "doughnut",
      data: {
        labels,
        datasets: [{
          data: values,
          backgroundColor: colors,
          borderColor: "#0d1321",
          borderWidth: 3,
          hoverOffset: 6,
        }]
      },
      options: {
        responsive: true,
        cutout: "68%",
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: "#131c2e",
            titleColor: "#e2e8f0",
            bodyColor: "#94a3b8",
            borderColor: "#1e2d45",
            borderWidth: 1,
            padding: 10,
            callbacks: {
              label: ctx => ` ${ctx.label}: ${ctx.parsed} events (${Math.round(ctx.parsed / ctx.dataset.data.reduce((a,b)=>a+b,0) * 100)}%)`
            }
          }
        },
        animation: { animateScale: true, duration: 600 },
      }
    });
  } else {
    donutChart.data.labels                      = labels;
    donutChart.data.datasets[0].data            = values;
    donutChart.data.datasets[0].backgroundColor = colors;
    donutChart.update("active");
  }

  // Rebuild custom HTML legend
  const legendEl = document.getElementById("chart-legend");
  legendEl.innerHTML = labels.map((s, i) => `
    <div class="legend-item">
      <div class="legend-dot" style="background:${colors[i]};"></div>
      <span style="text-transform:capitalize;">${s}</span>
      <span class="legend-count">${values[i]}</span>
    </div>`).join("");
}


// =============================================================================
// CHART.JS — TIMELINE SPARKLINE
// =============================================================================

function initTimelineChart() {
  const ctx = document.getElementById("timelineChart").getContext("2d");
  timelineChart = new Chart(ctx, {
    type: "line",
    data: {
      labels: timelineLabels,
      datasets: [{
        label: "Events/5s",
        data: timelineData,
        borderColor: "#3b82f6",
        backgroundColor: "rgba(59,130,246,0.08)",
        borderWidth: 2,
        fill: true,
        tension: 0.4,
        pointRadius: 0,
        pointHoverRadius: 4,
        pointHoverBackgroundColor: "#3b82f6",
      }]
    },
    options: {
      responsive: true,
      animation: { duration: 400 },
      interaction: { mode: "index", intersect: false },
      scales: {
        x: {
          display: true,
          ticks: { color: "#475569", font: { size: 9 }, maxTicksLimit: 6 },
          grid: { color: "rgba(30,45,69,0.6)" }
        },
        y: {
          display: true,
          beginAtZero: true,
          ticks: { color: "#475569", font: { size: 9 }, precision: 0 },
          grid: { color: "rgba(30,45,69,0.6)" }
        }
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: "#131c2e",
          titleColor: "#94a3b8",
          bodyColor: "#e2e8f0",
          borderColor: "#1e2d45",
          borderWidth: 1,
        }
      }
    }
  });
}

function pushTimelinePoint(count) {
  const now   = new Date();
  const label = now.toLocaleTimeString([], { hour12: false,
    hour: "2-digit", minute: "2-digit", second: "2-digit" });
  timelineData.push(count);
  timelineLabels.push(label);
  if (timelineData.length > TIMELINE_SLOTS)   timelineData.shift();
  if (timelineLabels.length > TIMELINE_SLOTS) timelineLabels.shift();

  if (timelineChart) {
    timelineChart.data.labels           = timelineLabels;
    timelineChart.data.datasets[0].data = timelineData;
    timelineChart.update("none");
  }
}


// =============================================================================
// EVENT TYPE BREAKDOWN LIST
// =============================================================================

function updateEventTypeBreakdown(byType) {
  const container = document.getElementById("event-type-breakdown");
  if (!byType || Object.keys(byType).length === 0) {
    container.innerHTML = `<div style="color:var(--text-muted); font-size:0.75rem; text-align:center; padding:1rem 0;">No data yet</div>`;
    return;
  }

  const maxCount = Math.max(...Object.values(byType));
  const sorted   = Object.entries(byType).sort((a,b) => b[1] - a[1]).slice(0, 6);

  container.innerHTML = sorted.map(([type, count]) => `
    <div class="event-type-item" style="position:relative;">
      <i class="bi bi-circle-fill" style="font-size:0.5em; color:var(--accent-blue);"></i>
      <span style="text-transform:capitalize; color:var(--text-secondary);">${type.replace(/_/g," ")}</span>
      <span class="count">${count}</span>
      <div style="position:absolute; bottom:0; left:0; right:0; padding:0 10px;">
        <div class="event-type-bar">
          <div class="event-type-bar-fill" style="width:${Math.round(count/maxCount*100)}%;"></div>
        </div>
      </div>
    </div>`).join("");
}


// =============================================================================
// POLLING — MAIN LOOP
// =============================================================================

/**
 * Incremental poll: fetch only events newer than `lastSeen`.
 * Runs every POLL_INTERVAL_MS (5s).
 */
async function pollEvents() {
  try {
    const severityFilter = document.getElementById("filter-severity").value;
    const typeFilter     = document.getElementById("filter-type").value;

    let url = `${API_BASE}/api/events?limit=50`;
    if (lastSeen)        url += `&since=${encodeURIComponent(lastSeen)}`;
    if (severityFilter)  url += `&severity=${encodeURIComponent(severityFilter)}`;

    const resp = await fetch(url);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

    const envelope = await resp.json();
    const data     = envelope.data;

    // Fetch full aggregate stats (no since-filter — always full DB scan)
    await fetchAndUpdateStats();

    const events = data.events || [];

    // Client-side type filter
    const filtered = typeFilter
      ? events.filter(e => e.event_type === typeFilter)
      : events;

    let newCount = 0;

    // Insert new events in reverse so newest is at top
    for (const evt of [...filtered].reverse()) {
      if (seenEventIds.has(evt.id)) continue;
      seenEventIds.add(evt.id);
      prependEventRow(evt);
      newCount++;

      if (!lastSeen || evt.received_at > lastSeen) {
        lastSeen = evt.received_at;
      }
    }

    updateTableCount();
    pushTimelinePoint(newCount);

    // Update last-poll timestamp
    lastSuccessfulPoll = new Date();
    consecutiveErrors  = 0;

    // Update live indicator
    const statusEl = document.getElementById("live-status");
    statusEl.textContent = newCount > 0
      ? `Live · +${newCount} new`
      : "Live · up to date";

    // Update last-updated label
    const lastUpdEl = document.getElementById("last-updated");
    if (lastUpdEl) lastUpdEl.textContent = `Last polled: ${formatTime(lastSuccessfulPoll.toISOString())}`;

  } catch (err) {
    consecutiveErrors++;
    console.error("[ZenGuard] Poll error:", err);
    const statusEl = document.getElementById("live-status");
    statusEl.textContent = consecutiveErrors > 3 ? "Disconnected" : "Reconnecting…";
  }
}

/**
 * Full refresh: reset cursor and re-fetch everything.
 * Called every FULL_REFRESH_MS (30s) to ensure stale views never persist.
 */
function fullRefresh() {
  console.debug("[ZenGuard] Running full table refresh");
  lastSeen = null;
  seenEventIds.clear();
  activeDatasetsSet.clear();
  document.getElementById("events-tbody").innerHTML = "";
  pollEvents();
}

/** Fetch aggregate stats and update KPI + charts */
async function fetchAndUpdateStats() {
  try {
    const resp = await fetch(`${API_BASE}/api/stats`);
    if (!resp.ok) return;
    const envelope = await resp.json();
    const stats    = envelope.data;

    updateKPICards(stats, stats.by_type || {});
    updateDonutChart(stats.by_severity || {});
    updateEventTypeBreakdown(stats.by_type || {});

  } catch (err) {
    console.warn("[ZenGuard] Stats fetch error:", err);
  }
}


// =============================================================================
// EVENT DETAIL MODAL — with Dataset Info section
// =============================================================================

async function showEventDetail(eventId) {
  const modal   = new bootstrap.Modal(document.getElementById("eventDetailModal"));
  const content = document.getElementById("modal-detail-content");
  content.innerHTML = `<div style="color:var(--text-muted); font-size:0.8rem; padding:1rem;">Loading…</div>`;
  modal.show();

  try {
    const resp = await fetch(`${API_BASE}/api/events/${encodeURIComponent(eventId)}`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const envelope  = await resp.json();
    const eventData = envelope.data;

    // --- Dataset info section ---
    const datasetKey   = eventData.dataset || "unknown";
    const meta         = getDatasetMeta(datasetKey);
    const attackCat    = eventData.attack_category || "—";
    const rawLabel     = eventData.raw_label || "—";

    // Dataset description lookup
    const datasetDesc = {
      "cic":       "CIC-IDS-2017 — Canadian Institute for Cybersecurity intrusion detection dataset. Contains labeled network flows from 5 attack days including DoS, DDoS, Brute Force, XSS, SQL Injection, Infiltration, Botnet, and Port Scan attacks.",
      "unsw":      "UNSW-NB15 — Network intrusion dataset from the Australian Centre for Cyber Security. Contains 9 attack categories: Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, and Worms.",
      "synthetic": "Synthetic — Algorithmically generated event using scenario triggers. These events simulate specific attack chains (Privilege Escalation, Brute Force, MFA Bypass) for pipeline validation and demo purposes.",
      "unknown":   "Source dataset could not be identified for this event.",
    };

    const descText = datasetDesc[datasetKey.toLowerCase()] || datasetDesc["unknown"];

    // UEBA features from the event
    const uebaFields = [
      ["failed_logins",             eventData.failed_logins,             "Count of failed login attempts before this event"],
      ["access_time",               eventData.access_time,               "Timestamp of the access attempt (synthesized from flow timing)"],
      ["session_duration",          eventData.session_duration,          "Duration of the network session in seconds"],
      ["device_trust_score",        eventData.device_trust_score,        "Trust score for the source device (0=untrusted, 1=fully managed)"],
      ["privilege_change_attempted",eventData.privilege_change_attempted,"1 if a privilege escalation was attempted, 0 otherwise"],
      ["external_connection",       eventData.external_connection,       "1 if source IP is external/non-RFC1918, 0 if internal"],
      ["MFA_bypassed",              eventData.MFA_bypassed,              "1 if multi-factor authentication was bypassed, 0 otherwise"],
    ];

    const uebaHtml = uebaFields.map(([key, val, hint]) => `
      <div style="
        display:flex; justify-content:space-between; align-items:flex-start;
        padding:6px 10px;
        background:var(--bg-elevated);
        border-radius:4px;
        gap:12px;
        margin-bottom:4px;
      ">
        <span style="font-family:var(--font-mono); font-size:0.72rem; color:var(--accent-cyan); flex-shrink:0;">${key}</span>
        <span style="font-size:0.72rem; color:var(--text-muted); text-align:right;">${hint}</span>
        <span style="font-family:var(--font-mono); font-size:0.75rem; color:var(--text-primary); font-weight:600; flex-shrink:0;">
          ${val !== undefined && val !== null ? val : "—"}
        </span>
      </div>`).join("");

    // Build key event fields for display (without raw_json itself)
    const displayFields = {
      event_id:    eventData.event_id,
      timestamp:   eventData.timestamp || eventData.access_time,
      src_ip:      eventData.src_ip,
      dst_ip:      eventData.dst_ip,
      src_port:    eventData.src_port,
      dst_port:    eventData.dst_port,
      protocol:    eventData.protocol,
      user_id:     eventData.user_id,
      hostname:    eventData.hostname,
      event_type:  eventData.event_type,
      action:      eventData.action,
      severity:    eventData.severity,
      log_source:  eventData.log_source,
      attack_category: attackCat,
    };

    content.innerHTML = `
      <!-- DATASET INFO SECTION -->
      <div style="
        background: linear-gradient(135deg, ${meta.color}12, ${meta.color}06);
        border: 1px solid ${meta.color}35;
        border-radius: 8px;
        padding: 1rem;
        margin-bottom: 1rem;
      ">
        <div style="display:flex; align-items:center; gap:10px; margin-bottom:0.6rem;">
          <i class="bi ${meta.icon}" style="color:${meta.color}; font-size:1.2rem;"></i>
          <div>
            <div style="font-weight:700; color:var(--text-primary); font-size:0.88rem;">${meta.label}</div>
            <div style="font-size:0.68rem; color:var(--text-muted); letter-spacing:0.8px; text-transform:uppercase;">Dataset Source</div>
          </div>
        </div>
        <p style="font-size:0.75rem; color:var(--text-secondary); line-height:1.6; margin:0 0 0.6rem 0;">${descText}</p>
        <div style="display:flex; gap:8px; flex-wrap:wrap;">
          <span style="font-size:0.68rem; background:${meta.color}18; border:1px solid ${meta.color}30; color:${meta.color}; padding:2px 8px; border-radius:4px;">
            Attack Category: <strong>${attackCat}</strong>
          </span>
          <span style="font-size:0.68rem; background:rgba(100,116,139,0.15); border:1px solid rgba(100,116,139,0.3); color:var(--text-secondary); padding:2px 8px; border-radius:4px;">
            Raw Label: <strong>${rawLabel}</strong>
          </span>
        </div>
      </div>

      <!-- EVENT FIELDS -->
      <div style="margin-bottom:1rem;">
        <div style="font-size:0.7rem; font-weight:600; letter-spacing:1px; text-transform:uppercase; color:var(--text-muted); margin-bottom:0.5rem;">
          <i class="bi bi-card-list me-1"></i>Event Fields
        </div>
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:4px;">
          ${Object.entries(displayFields).filter(([,v]) => v !== undefined && v !== null).map(([k, v]) => `
            <div style="
              display:flex; gap:8px; align-items:center;
              padding:5px 8px;
              background:var(--bg-elevated);
              border-radius:4px;
              overflow:hidden;
            ">
              <span style="font-family:var(--font-mono); font-size:0.65rem; color:var(--text-muted); flex-shrink:0;">${k}</span>
              <span style="font-family:var(--font-mono); font-size:0.72rem; color:var(--text-primary); overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${v}">${v}</span>
            </div>`).join("")}
        </div>
      </div>

      <!-- UEBA FEATURES -->
      <div>
        <div style="font-size:0.7rem; font-weight:600; letter-spacing:1px; text-transform:uppercase; color:var(--text-muted); margin-bottom:0.5rem;">
          <i class="bi bi-cpu me-1"></i>UEBA Behavioral Features
          <span style="font-size:0.6rem; font-weight:400; color:var(--text-muted); margin-left:6px;">Synthesized from ${meta.label} network flow</span>
        </div>
        ${uebaHtml}
      </div>
    `;

  } catch (err) {
    content.innerHTML = `<div style="color:var(--sev-critical); font-size:0.8rem; padding:1rem;">Error loading event: ${err.message}</div>`;
  }
}


// =============================================================================
// TOAST NOTIFICATIONS
// =============================================================================

function showToast(message, type = "info") {
  const container = document.getElementById("toast-container");
  const id        = "toast-" + Date.now();

  const iconMap = {
    success: "bi-check-circle-fill",
    error:   "bi-exclamation-octagon-fill",
    info:    "bi-info-circle-fill",
  };

  const colorMap = {
    success: "var(--accent-green)",
    error:   "var(--sev-critical)",
    info:    "var(--accent-blue)",
  };

  const html = `
    <div id="${id}" class="toast zenguard-toast ${type}" role="alert" aria-live="assertive">
      <div class="toast-body d-flex align-items-start gap-2" style="padding:12px 16px;">
        <i class="bi ${iconMap[type]}" style="color:${colorMap[type]}; margin-top:2px; flex-shrink:0;"></i>
        <div style="flex:1; font-size:0.78rem; color:var(--text-primary);">${message}</div>
        <button type="button" class="btn-close" data-bs-dismiss="toast"
                style="filter:invert(1) opacity(0.4); flex-shrink:0;"></button>
      </div>
    </div>`;

  container.insertAdjacentHTML("beforeend", html);

  const toastEl = document.getElementById(id);
  const toast   = new bootstrap.Toast(toastEl, { delay: 5000 });
  toast.show();

  toastEl.addEventListener("hidden.bs.toast", () => toastEl.remove());
}


// =============================================================================
// TOPBAR CLOCK
// =============================================================================

function startClock() {
  function tick() {
    const now = new Date();
    document.getElementById("topbar-clock").textContent =
      now.toLocaleString([], {
        year: "numeric", month: "2-digit", day: "2-digit",
        hour: "2-digit", minute: "2-digit", second: "2-digit",
        hour12: false
      });
  }
  tick();
  setInterval(tick, 1000);
}


// =============================================================================
// EVENT DELEGATION
// =============================================================================

document.getElementById("events-tbody").addEventListener("click", (e) => {
  const detailBtn = e.target.closest("button[data-detail-id]");
  if (detailBtn) {
    showEventDetail(detailBtn.dataset.detailId);
  }
});

// Manual refresh button
document.getElementById("btn-refresh").addEventListener("click", () => {
  fullRefresh();
  showToast("Manual refresh triggered — fetching latest events.", "info");
});

// Severity filter: full reset + re-poll
document.getElementById("filter-severity").addEventListener("change", () => {
  lastSeen = null;
  seenEventIds.clear();
  document.getElementById("events-tbody").innerHTML = "";
  pollEvents();
});

// Type filter: client-side only (no cursor reset needed)
document.getElementById("filter-type").addEventListener("change", () => {
  seenEventIds.clear();
  document.getElementById("events-tbody").innerHTML = "";
  pollEvents();
});


// =============================================================================
// STARTUP
// =============================================================================

(function init() {
  startClock();
  initTimelineChart();

  // Immediate first poll
  pollEvents();

  // Incremental poll every 5s
  pollingTimer = setInterval(pollEvents, POLL_INTERVAL_MS);

  // Full table refresh every 30s to prevent stale views
  fullRefreshTimer = setInterval(fullRefresh, FULL_REFRESH_MS);

  showToast("ZenGuard SIEM connected — polling every 5s, full refresh every 30s.", "info");
})();
