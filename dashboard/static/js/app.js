/**
 * ============================================================================
 * File: dashboard/static/js/app.js
 * Project: ZenGuard Zero Trust SIEM — Phase 6: Frontend Logic
 *
 * Description:
 *   All client-side logic for the ZenGuard dashboard. Responsibilities:
 *     1. Polling /api/events every 2 seconds (incremental, not full-reload).
 *     2. Rendering events into the live events table with animations.
 *     3. Updating all 5 KPI cards from aggregated stats.
 *     4. Driving the Chart.js donut chart (severity distribution).
 *     5. Driving the Chart.js line chart (timeline sparkline).
 *     6. Firing SOAR action POST requests and showing toast feedback.
 *     7. Populating the event detail modal with raw JSON.
 *
 * Architecture:
 *   This file is intentionally vanilla JS (no framework). The reasons:
 *     - No build step required — works directly with Flask's static serving.
 *     - Easier to inspect in a security audit (no transpiled/minified code).
 *     - The DOM manipulation is simple enough that React/Vue adds more
 *       complexity than it removes for this use-case.
 * ============================================================================
 */

"use strict";

// =============================================================================
// GLOBALS & STATE
// =============================================================================

const API_BASE         = "";          // empty = same origin (Flask on port 5000)
const POLL_INTERVAL_MS = 2000;        // poll /api/events every 2 seconds
const MAX_TABLE_ROWS   = 100;         // keep the DOM lean

// State: track the newest event's received_at timestamp to implement
// incremental polling. We only fetch events newer than lastSeen,
// avoiding re-rendering the entire table on every tick.
let lastSeen         = null;
let pollingTimer     = null;
let soarActionCount  = 0;
let donutChart       = null;
let timelineChart    = null;
let seenEventIds     = new Set();   // client-side dedup guard

// Timeline buffer: 30 slots × 2s = 60-second rolling window
const TIMELINE_SLOTS = 30;
let timelineData     = new Array(TIMELINE_SLOTS).fill(0);
let timelineLabels   = new Array(TIMELINE_SLOTS).fill("");


// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/**
 * Format an ISO8601 timestamp into a short HH:MM:SS string for table display.
 * Times are shown in the browser's local timezone for operator ergonomics.
 */
function formatTime(isoString) {
  if (!isoString) return "—";
  try {
    const d = new Date(isoString);
    return d.toLocaleTimeString([], { hour12: false,
      hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch { return isoString; }
}

/**
 * Return a color hex string for a given severity level.
 * Centralized here so changes propagate to all chart/table consumers.
 */
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

/**
 * Build the inline risk score bar HTML string.
 * Bar width = risk_score percent; color interpolates red→yellow→green.
 */
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

/**
 * Build the SOAR action buttons cell for a table row.
 * If a SOAR action has already been taken (soar_action field is set),
 * replace the buttons with a "done" badge instead of allowing re-triggering.
 */
function buildActionsCell(event) {
  if (event.soar_action) {
    return `<span class="soar-done-badge">
              <i class="bi bi-check-circle-fill"></i> ${event.soar_action}
            </span>`;
  }

  return `
    <div style="display:flex; gap:5px; flex-wrap:wrap;">
      <button class="action-btn btn-block-ip"
              data-action="block_ip"
              data-event-id="${event.id}"
              data-src-ip="${event.src_ip || ''}"
              title="Block source IP: ${event.src_ip || 'N/A'}">
        <i class="bi bi-shield-fill-x"></i> Block IP
      </button>
      <button class="action-btn btn-isolate"
              data-action="isolate"
              data-event-id="${event.id}"
              data-endpoint-id="${event.endpoint_id || ''}"
              title="Isolate endpoint: ${event.endpoint_id || 'N/A'}">
        <i class="bi bi-pc-display-horizontal"></i> Isolate
      </button>
      <button class="action-btn btn-mfa"
              data-action="mfa"
              data-event-id="${event.id}"
              data-user-id="${event.user_id || ''}"
              title="Enforce MFA for: ${event.user_id || 'N/A'}">
        <i class="bi bi-person-lock"></i> MFA
      </button>
      <button class="action-btn btn-whitelist"
              data-action="whitelist"
              data-event-id="${event.id}"
              data-src-ip="${event.src_ip || ''}"
              title="Mark as false positive">
        <i class="bi bi-check2"></i>
      </button>
    </div>`;
}


// =============================================================================
// TABLE RENDERING
// =============================================================================

/**
 * Insert a single event as a new <tr> at the top of the events table.
 * The "new-row" CSS class triggers the slide-in animation defined in index.html.
 * Old rows beyond MAX_TABLE_ROWS are pruned from the bottom to keep the
 * DOM size bounded (prevents memory leak in long-running browser sessions).
 */
function prependEventRow(event) {
  const tbody = document.getElementById("events-tbody");

  // Remove the "waiting for events" placeholder row if present
  const emptyRow = tbody.querySelector("#events-empty");
  if (emptyRow) emptyRow.remove();

  const tr = document.createElement("tr");
  tr.classList.add("new-row");
  tr.dataset.eventId = event.id;

  const sev       = (event.severity || "unknown").toLowerCase();
  const eventType = event.event_type || "unknown";
  const row_src   = event.src_ip    || "—";
  const userId    = event.user_id   || "—";
  const device    = event.endpoint_id ? `${event.endpoint_id}<br><span class="td-mono" style="color:var(--text-muted)">${row_src}</span>` : row_src;

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
    <td>${buildActionsCell(event)}</td>
    <td>
      <button class="action-btn btn-whitelist"
              data-detail-id="${event.id}"
              style="color:var(--accent-blue); border-color:rgba(59,130,246,0.3);">
        <i class="bi bi-search"></i> Detail
      </button>
    </td>`;

  tbody.insertBefore(tr, tbody.firstChild);

  // Prune overflow rows from the bottom
  const rows = tbody.querySelectorAll("tr");
  if (rows.length > MAX_TABLE_ROWS) {
    for (let i = MAX_TABLE_ROWS; i < rows.length; i++) {
      rows[i].remove();
    }
  }
}

/** Update the table row count badge in the card header */
function updateTableCount() {
  const count = document.querySelectorAll("#events-tbody tr:not(#events-empty)").length;
  document.getElementById("table-count").textContent = count;
}


// =============================================================================
// KPI CARD UPDATES
// =============================================================================

/**
 * Animate a numeric KPI value change using a simple counter sweep.
 * Provides the "counting up" effect seen in premium dashboards.
 */
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

/**
 * Update all 5 KPI cards from the /api/events response data object.
 */
function updateKPICards(data) {
  const bySev = data.by_severity || {};

  animateCounter("kpi-total",        data.total || 0);
  animateCounter("kpi-high-risk",    data.high_risk || 0);
  animateCounter("kpi-critical",     bySev.critical || 0);
  animateCounter("kpi-failed-logins",(data.by_type || {}).failed_logins || 0);
  animateCounter("kpi-soar-actions", soarActionCount);
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

/** Initialize or update the Chart.js donut chart. */
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
          legend: { display: false },   // custom legend built below
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
    donutChart.data.labels             = labels;
    donutChart.data.datasets[0].data   = values;
    donutChart.data.datasets[0].backgroundColor = colors;
    donutChart.update("active");
  }

  // Rebuild the custom HTML legend below the chart
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

/** Initialize the timeline line chart once. */
function initTimelineChart() {
  const ctx = document.getElementById("timelineChart").getContext("2d");
  timelineChart = new Chart(ctx, {
    type: "line",
    data: {
      labels: timelineLabels,
      datasets: [{
        label: "Events/2s",
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

/** Push a new data point onto the rolling 60-second timeline. */
function pushTimelinePoint(count) {
  const now = new Date();
  const label = now.toLocaleTimeString([], { hour12: false, hour: "2-digit",
                                             minute: "2-digit", second: "2-digit" });
  timelineData.push(count);
  timelineLabels.push(label);
  if (timelineData.length > TIMELINE_SLOTS)  timelineData.shift();
  if (timelineLabels.length > TIMELINE_SLOTS) timelineLabels.shift();

  if (timelineChart) {
    timelineChart.data.labels            = timelineLabels;
    timelineChart.data.datasets[0].data  = timelineData;
    timelineChart.update("none");   // "none" skips animation for performance
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
    <div class="event-type-item">
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
 * Core polling function. Called every POLL_INTERVAL_MS.
 * Uses the `since` parameter to only fetch events the client hasn't seen,
 * making each poll efficient regardless of total event volume in the DB.
 */
async function pollEvents() {
  try {
    // Build query: filter by severity if the select is non-empty
    const severityFilter = document.getElementById("filter-severity").value;
    const typeFilter     = document.getElementById("filter-type").value;

    let url = `${API_BASE}/api/events?limit=50`;
    if (lastSeen) url += `&since=${encodeURIComponent(lastSeen)}`;
    if (severityFilter) url += `&severity=${encodeURIComponent(severityFilter)}`;

    const resp = await fetch(url);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

    const envelope = await resp.json();
    const data     = envelope.data;

    // Update charts and KPI from the ALL-EVENTS aggregation endpoint
    // (we fetch stats separately to avoid the `since` filter skewing counts)
    fetchAndUpdateStats();

    const events = data.events || [];

    // Apply client-side type filter (server doesn't support type filter yet)
    const filtered = typeFilter
      ? events.filter(e => e.event_type === typeFilter)
      : events;

    let newCount = 0;

    // Insert new events in reverse order so newest appears at the top
    for (const evt of [...filtered].reverse()) {
      if (seenEventIds.has(evt.id)) continue;   // client-side dedup
      seenEventIds.add(evt.id);
      prependEventRow(evt);
      newCount++;

      // Track the most recent received_at for next poll's `since` parameter
      if (!lastSeen || evt.received_at > lastSeen) {
        lastSeen = evt.received_at;
      }
    }

    updateTableCount();
    pushTimelinePoint(newCount);

    // Update live status indicator
    document.getElementById("live-status").textContent = "Live";

  } catch (err) {
    console.error("[ZenGuard] Poll error:", err);
    document.getElementById("live-status").textContent = "Reconnecting…";
  }
}

/** Fetch aggregate stats independently (no `since` filter — full DB scan) */
async function fetchAndUpdateStats() {
  try {
    const resp = await fetch(`${API_BASE}/api/stats`);
    if (!resp.ok) return;
    const envelope = await resp.json();
    const stats    = envelope.data;

    // KPI cards
    document.getElementById("kpi-total").textContent     = stats.total     || 0;
    document.getElementById("kpi-high-risk").textContent = stats.high_risk || 0;
    document.getElementById("kpi-critical").textContent  = (stats.by_severity || {}).critical || 0;

    // Charts
    updateDonutChart(stats.by_severity || {});

  } catch (err) {
    console.warn("[ZenGuard] Stats fetch error:", err);
  }
}


// =============================================================================
// SOAR ACTION HANDLER
// =============================================================================

/**
 * Dispatch a SOAR action POST request to the Flask backend.
 * The action type, event_id, and relevant metadata are read from the
 * button's data-* attributes so each button is self-contained.
 */
async function dispatchSoarAction(btn) {
  const action     = btn.dataset.action;
  const eventId    = btn.dataset.eventId;
  const srcIp      = btn.dataset.srcIp      || "";
  const endpointId = btn.dataset.endpointId || "";
  const userId     = btn.dataset.userId     || "";

  // Map action name → API endpoint
  const endpointMap = {
    block_ip:  "/api/soar/block_ip",
    isolate:   "/api/soar/isolate",
    mfa:       "/api/soar/mfa",
    whitelist: "/api/soar/whitelist",
  };

  const apiEndpoint = endpointMap[action];
  if (!apiEndpoint) { console.warn("Unknown SOAR action:", action); return; }

  // Build the request body
  const body = { event_id: eventId };
  if (srcIp)      body.src_ip      = srcIp;
  if (endpointId) body.endpoint_id = endpointId;
  if (userId)     body.user_id     = userId;

  // Visually disable the button row during the request
  const actionsCell = btn.closest("td");
  actionsCell.style.opacity = "0.5";
  actionsCell.style.pointerEvents = "none";

  try {
    const resp = await fetch(`${API_BASE}${apiEndpoint}`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify(body),
    });

    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const envelope = await resp.json();
    const result   = envelope.data;

    // Replace buttons with "done" badge
    actionsCell.innerHTML = `
      <span class="soar-done-badge">
        <i class="bi bi-check-circle-fill"></i> ${result.action || action}
      </span>`;

    soarActionCount++;
    animateCounter("kpi-soar-actions", soarActionCount);

    showToast(`SOAR: ${result.detail || "Action executed"}`, "success");

  } catch (err) {
    actionsCell.style.opacity      = "1";
    actionsCell.style.pointerEvents = "auto";
    showToast(`SOAR action failed: ${err.message}`, "error");
    console.error("[ZenGuard] SOAR error:", err);
  }
}


// =============================================================================
// EVENT DETAIL MODAL
// =============================================================================

async function showEventDetail(eventId) {
  const modal   = new bootstrap.Modal(document.getElementById("eventDetailModal"));
  const content = document.getElementById("modal-json-content");
  content.textContent = "Loading…";
  modal.show();

  try {
    const resp = await fetch(`${API_BASE}/api/events/${encodeURIComponent(eventId)}`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const envelope = await resp.json();
    content.textContent = JSON.stringify(envelope.data, null, 2);
  } catch (err) {
    content.textContent = `Error loading event: ${err.message}`;
  }
}


// =============================================================================
// TOAST NOTIFICATIONS
// =============================================================================

/**
 * Show a temporary toast notification at the bottom-right corner.
 * type: "success" | "error" | "info"
 */
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
// EVENT DELEGATION — single listener on the table body handles all buttons
// =============================================================================

document.getElementById("events-tbody").addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-action]");
  if (btn) {
    dispatchSoarAction(btn);
    return;
  }

  const detailBtn = e.target.closest("button[data-detail-id]");
  if (detailBtn) {
    showEventDetail(detailBtn.dataset.detailId);
  }
});

// Manual refresh button
document.getElementById("btn-refresh").addEventListener("click", () => {
  lastSeen = null;       // reset cursor to fetch all recent events
  seenEventIds.clear();
  document.getElementById("events-tbody").innerHTML = "";
  pollEvents();
  showToast("Table refreshed — fetching latest events.", "info");
});

// Filter change: reset cursor and re-poll immediately
document.getElementById("filter-severity").addEventListener("change", () => {
  lastSeen = null;
  seenEventIds.clear();
  document.getElementById("events-tbody").innerHTML = "";
  pollEvents();
});

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

  // Begin polling immediately, then repeat on interval
  pollEvents();
  pollingTimer = setInterval(pollEvents, POLL_INTERVAL_MS);

  showToast("ZenGuard Listener connected — polling every 2s.", "info");
})();
