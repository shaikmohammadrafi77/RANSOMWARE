/**
 * CORTEX Defense System — Frontend Application
 * Auto-refresh every 5 seconds, Chart.js visualizations,
 * Role-based UI, incident management, reporting.
 */

const API = "/api";
let currentUser = null;
let currentManageIncidentId = null;
let autoRefreshTimer = null;
let countdownInterval = null;
let charts = {};
const REFRESH_INTERVAL = 5000; // 5 seconds

// ─── Toast Notification ───────────────────────────────────────
function showToast(msg, type = "info") {
  const toast = document.getElementById("toast");
  if (!toast) return;
  const colors = { info: "#00d4ff", success: "#00ffa3", error: "#ff3355", warning: "#ffaa00" };
  toast.style.display = "block";
  toast.style.borderColor = colors[type] || colors.info;
  toast.innerHTML = msg;
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => { toast.style.display = "none"; }, 3500);
}

// ─── Session & Auth ────────────────────────────────────────────
async function checkSession() {
  try {
    const res = await fetch(`${API}/me`);
    if (res.status === 401 || res.status === 403) {
      window.location.href = "/login";
      return false;
    }
    const data = await res.json();
    if (data.status === "ok" && data.user) {
      currentUser = data.user;
      updateUserUI(data.user);
      return true;
    }
  } catch (_) { }
  return false;
}

function updateUserUI(user) {
  const initials = (user.username || "?").substring(0, 2).toUpperCase();
  const role = (user.role || "VIEWER").toUpperCase();

  const avatar = document.getElementById("sidebarAvatar");
  const uname = document.getElementById("sidebarUsername");
  const roleBadge = document.getElementById("sidebarRoleBadge");

  if (avatar) avatar.textContent = initials;
  if (uname) uname.textContent = user.username;
  if (roleBadge) {
    roleBadge.textContent = role;
    roleBadge.className = "user-role-badge";
    if (role === "ADMIN") roleBadge.style.color = "#ff3355";
    if (role === "ANALYST") roleBadge.style.color = "#ffaa00";
  }

  // Show/hide manage button depending on role
  document.querySelectorAll(".btn-manage").forEach(btn => {
    btn.style.display = (role === "VIEWER") ? "none" : "";
  });
}

async function handleLogout() {
  try {
    await fetch(`${API}/logout`, { method: "POST", credentials: "include" });
  } catch (_) { }
  window.location.replace("/login");
}

// ─── Navigation ────────────────────────────────────────────────
function setupNavigation() {
  document.querySelectorAll(".nav-item").forEach(item => {
    item.addEventListener("click", e => {
      e.preventDefault();
      document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));
      item.classList.add("active");
      switchView(item.getAttribute("data-view"));
    });
  });
}

function switchView(name) {
  document.querySelectorAll(".view-section").forEach(el => el.style.display = "none");
  const target = document.getElementById(`view-${name}`);
  if (target) target.style.display = "block";

  const titles = {
    dashboard: ["Security Operations Center", "Real-time threat detection and active prevention"],
    incidents: ["Incident Registry", "Full incident lifecycle management"],
    model: ["AI Model Diagnostics", "Neural network performance and version history"],
    reports: ["Reporting Center", "Export data and generate security summaries"],
  };

  const [title, sub] = titles[name] || ["Cortex", ""];
  const pt = document.getElementById("pageTitle");
  const ps = document.getElementById("pageSubtitle");
  if (pt) pt.textContent = title;
  if (ps) ps.textContent = sub;

  if (name === "model") loadModelView();
  if (name === "reports") loadSystemSummary();
}

// ─── Charts Setup ──────────────────────────────────────────────
const CHART_DEFAULTS = {
  color: "#6b7fa4",
  backgroundColor: "transparent",
  borderColor: "transparent",
};

Chart.defaults.color = "#6b7fa4";
Chart.defaults.font.family = "'Inter', sans-serif";
Chart.defaults.font.size = 11;
Chart.defaults.plugins.legend.display = false;

function getOrCreateChart(id, config) {
  const existing = charts[id];
  if (existing) {
    // Just return the existing chart for data updates
    return existing;
  }
  const canvas = document.getElementById(id);
  if (!canvas) return null;
  const chart = new Chart(canvas, config);
  charts[id] = chart;
  return chart;
}

function initCharts() {
  // CPU Trend chart
  getOrCreateChart("cpuChart", {
    type: "line",
    data: {
      labels: [],
      datasets: [{
        data: [],
        borderColor: "#00d4ff",
        backgroundColor: "rgba(0,212,255,0.08)",
        fill: true,
        tension: 0.4,
        pointRadius: 2,
        borderWidth: 2,
      }]
    },
    options: {
      animation: false,
      scales: {
        x: { display: false },
        y: {
          min: 0, max: 100,
          grid: { color: "rgba(255,255,255,0.04)" },
          ticks: { callback: v => `${v}%`, maxTicksLimit: 5 }
        }
      },
      plugins: { legend: { display: false }, tooltip: { callbacks: { label: ctx => `${ctx.raw.toFixed(1)}%` } } }
    }
  });

  // Threat Trend chart
  getOrCreateChart("threatChart", {
    type: "bar",
    data: {
      labels: [],
      datasets: [{
        data: [],
        backgroundColor: "rgba(255,51,85,0.5)",
        borderColor: "#ff3355",
        borderWidth: 1,
        borderRadius: 4,
      }]
    },
    options: {
      animation: false,
      scales: {
        x: { grid: { display: false }, ticks: { maxTicksLimit: 7 } },
        y: { grid: { color: "rgba(255,255,255,0.04)" }, ticks: { stepSize: 1 } }
      },
      plugins: { legend: { display: false } }
    }
  });

  // Severity Distribution (doughnut)
  getOrCreateChart("severityChart", {
    type: "doughnut",
    data: {
      labels: ["Critical", "High", "Medium", "Low"],
      datasets: [{
        data: [0, 0, 0, 0],
        backgroundColor: ["rgba(255,51,85,0.8)", "rgba(255,170,0,0.8)", "rgba(255,208,0,0.7)", "rgba(107,127,164,0.5)"],
        borderColor: ["#ff3355", "#ffaa00", "#ffd000", "#3a4560"],
        borderWidth: 1,
        hoverOffset: 4,
      }]
    },
    options: {
      animation: false,
      cutout: "65%",
      plugins: {
        legend: {
          display: true,
          position: "bottom",
          labels: { font: { size: 10 }, boxWidth: 10, padding: 8 }
        }
      }
    }
  });
}

function updateCpuChart(history) {
  const chart = charts["cpuChart"];
  if (!chart || !Array.isArray(history)) return;
  chart.data.labels = history.map(p => new Date(p.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }));
  chart.data.datasets[0].data = history.map(p => p.cpu_usage);
  chart.update("none");
}

function updateThreatChart(trend) {
  const chart = charts["threatChart"];
  if (!chart || !Array.isArray(trend)) return;
  chart.data.labels = trend.map(t => t.day ? t.day.slice(5) : "");
  chart.data.datasets[0].data = trend.map(t => t.count);
  chart.update("none");
}

function updateSeverityChart(dist) {
  const chart = charts["severityChart"];
  if (!chart || !Array.isArray(dist)) return;
  const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  chart.data.datasets[0].data = order.map(s => {
    const found = dist.find(d => (d.severity_level || "").toUpperCase() === s);
    return found ? found.count : 0;
  });
  chart.update("none");
}

// ─── Data Fetching ─────────────────────────────────────────────
async function fetchHealth() {
  try {
    const res = await fetch(`${API}/system_health`);
    if (!res.ok) return;
    const data = await res.json();

    // KPI cards
    setEl("cpuUsage", (data.cpu_usage ?? 0).toFixed(1));
    setEl("memoryUsage", (data.memory_usage ?? 0).toFixed(1));
    setEl("totalIncidents", data.total_incidents ?? 0);
    setEl("ransomwareIncidents", data.ransomware_incidents ?? 0);
    setEl("blockedCount", data.blocked_count ?? 0);
    setEl("preventionRate", `${((data.prevention_success_rate ?? 0) * 100).toFixed(0)}%`);

    const cpu = data.cpu_usage ?? 0;
    const mem = data.memory_usage ?? 0;
    setStyle("cpuBar", "width", `${Math.min(100, cpu)}%`);
    setStyle("memoryBar", "width", `${Math.min(100, mem)}%`);

    // Model accuracy
    const m = data.model_metrics || {};
    const accuracy = m.accuracy ?? 0;
    setEl("modelAccuracy", accuracy ? `${(accuracy * 100).toFixed(1)}%` : "Train req.");
    setEl("modelVersionBadge", `v${data.model_version || "--"}`);

    // Charts
    updateCpuChart(data.cpu_history || []);
    updateThreatChart(data.threat_trend || []);
    updateSeverityChart(data.severity_distribution || []);

    // Health indicator sidebar
    updateHealthIndicators({ server_status: "ok", database_status: "ok", model_status: data.model_name ? "loaded" : "missing" });

  } catch (err) {
    console.error("Health fetch failed:", err.message);
  }
}

async function fetchHealthStatus() {
  try {
    const res = await fetch(`${API}/health`);
    const data = await res.json();
    updateHealthIndicators(data);
  } catch (_) { }
}

function updateHealthIndicators(data) {
  updateStatusDot("sidebarServerDot", "sidebarServerStatus", data.server_status === "ok" ? "online" : "error", "Server Online", "Server Error");
  updateStatusDot("sidebarDbDot", "sidebarDbStatus", data.database_status === "ok" ? "online" : "error", "Database OK", "DB Error");
  updateStatusDot("sidebarModelDot", "sidebarModelStatus", data.model_status === "loaded" ? "online" : "warning", `Model v${data.model_version || "--"}`, "Model Missing");
}

function updateStatusDot(dotId, textId, cls, okText, errText) {
  const dot = document.getElementById(dotId);
  const text = document.getElementById(textId);
  if (dot) { dot.className = `status-dot ${cls}`; }
  if (text) { text.textContent = cls === "online" ? okText : errText; }
}

// ─── Incidents ─────────────────────────────────────────────────
let cachedIncidents = [];
let currentFilters = {};

async function fetchIncidents(filters = {}) {
  try {
    const params = new URLSearchParams();
    if (filters.severity) params.set("severity", filters.severity);
    if (filters.status) params.set("status", filters.status);
    params.set("limit", "200");

    const res = await fetch(`${API}/incidents?${params}`);
    if (!res.ok) return;
    const json = await res.json();
    const data = json.data || json; // handle paginated or array
    cachedIncidents = Array.isArray(data) ? data : [];

    // Apply client-side label filter
    let filtered = cachedIncidents;
    if (filters.label) {
      filtered = filtered.filter(r => r.prediction_label === filters.label);
    }

    renderDashboardTable(filtered.slice(0, 8));
    renderFullTable(filtered);

    // Open incidents badge
    const openCount = cachedIncidents.filter(r => r.status === "OPEN").length;
    const badge = document.getElementById("openIncidentsBadge");
    if (badge) {
      badge.textContent = openCount;
      badge.classList.toggle("visible", openCount > 0);
    }

    const countEl = document.getElementById("incidentCountLabel");
    if (countEl) countEl.textContent = `${filtered.length} records`;

  } catch (err) {
    console.error("Incidents fetch failed:", err.message);
  }
}

function renderDashboardTable(rows) {
  const tbody = document.getElementById("dashboardTableBody");
  if (!tbody) return;

  if (!rows || rows.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="empty-state"><i class="fa-solid fa-inbox"></i> No incidents recorded yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = "";
  rows.forEach(row => tbody.appendChild(createDashboardRow(row)));
}

function renderFullTable(rows) {
  const tbody = document.getElementById("fullIncidentTableBody");
  if (!tbody) return;

  if (!rows || rows.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9" class="empty-state"><i class="fa-solid fa-inbox"></i> No incidents found.</td></tr>`;
    return;
  }

  tbody.innerHTML = "";
  rows.forEach(row => tbody.appendChild(createFullRow(row)));

  // Bind manage buttons
  tbody.querySelectorAll(".btn-manage").forEach(btn => {
    btn.addEventListener("click", () => openIncidentModal(btn.dataset));
  });
}

function createDashboardRow(row) {
  const tr = document.createElement("tr");
  const isRansomware = row.prediction_label === "ransomware";
  const ts = new Date(row.timestamp).toLocaleString([], { dateStyle: "short", timeStyle: "short" });

  tr.innerHTML = `
    <td style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;color:var(--text-secondary)">${ts}</td>
    <td>${escHtml(row.hostname || "unknown")}</td>
    <td>${isRansomware
      ? `<span class="badge badge-ransomware"><i class="fa-solid fa-skull-crossbones"></i> Ransomware</span>`
      : `<span class="badge badge-normal"><i class="fa-solid fa-check"></i> Normal</span>`
    }</td>
    <td style="font-family:'JetBrains Mono',monospace">${((row.prediction_score || 0) * 100).toFixed(1)}%</td>
    <td>${severityBadge(row.severity_level)}</td>
    <td>${preventionBadge(row.prevention_status)}</td>
  `;
  return tr;
}

function createFullRow(row) {
  const tr = document.createElement("tr");
  const role = (currentUser?.role || "VIEWER").toUpperCase();
  const canManage = role !== "VIEWER";
  const ts = new Date(row.timestamp).toLocaleString([], { dateStyle: "short", timeStyle: "short" });
  const incId = (row.incident_id || row.id || "").toString();
  const shortId = incId.length > 12 ? incId.substring(0, 8) + "…" : incId;

  const resTime = row.resolution_time
    ? new Date(row.resolution_time).toLocaleString([], { dateStyle: "short", timeStyle: "short" })
    : "<span style='color:var(--text-muted)'>—</span>";

  tr.innerHTML = `
    <td>
      <span title="${incId}" style="font-family:'JetBrains Mono',monospace;font-size:0.68rem;color:var(--text-secondary)">${shortId}</span>
    </td>
    <td style="font-size:0.78rem;color:var(--text-secondary)">${ts}</td>
    <td>${escHtml(row.hostname || "unknown")}</td>
    <td>${row.prediction_label === "ransomware"
      ? `<span class="badge badge-ransomware">Ransomware</span>`
      : `<span class="badge badge-normal">Normal</span>`}</td>
    <td>${severityBadge(row.severity_level)}</td>
    <td>${statusBadge(row.status)}</td>
    <td>${preventionBadge(row.prevention_status)}</td>
    <td style="font-size:0.72rem">${resTime}</td>
    <td>
      ${canManage
      ? `<button class="btn-manage"
             data-id="${incId}"
             data-sev="${row.severity_level || "LOW"}"
             data-stat="${row.status || "OPEN"}"
             data-comm="${encodeURIComponent(row.analyst_comments || "")}"
             data-timeline="${encodeURIComponent(row.analyst_comments || "")}">
             <i class="fa-solid fa-pen-to-square"></i> Manage
           </button>`
      : `<span style="color:var(--text-muted);font-size:0.72rem">View only</span>`
    }
    </td>
  `;
  return tr;
}

// ─── Incident Modal ────────────────────────────────────────────
function openIncidentModal({ id, sev, stat, comm, timeline }) {
  currentManageIncidentId = id;
  setEl("modalIncidentId", id ? `#${id.substring(0, 12)}` : "");

  const sevEl = document.getElementById("modalSeverity");
  const statEl = document.getElementById("modalStatus");
  const commEl = document.getElementById("modalComments");
  const tl = document.getElementById("incidentTimeline");

  if (sevEl) sevEl.value = (sev || "LOW").toUpperCase();
  if (statEl) statEl.value = (stat || "OPEN").toUpperCase();
  if (commEl) commEl.value = decodeURIComponent(comm || "");

  // Render timeline from comments
  if (tl) {
    const raw = decodeURIComponent(timeline || "");
    if (raw.trim()) {
      const entries = raw.split("\n").filter(Boolean);
      tl.innerHTML = entries.map(e => `<div class="timeline-entry">${escHtml(e)}</div>`).join("");
    } else {
      tl.innerHTML = "";
    }
  }

  document.getElementById("incidentModal").style.display = "flex";
}

async function saveIncident() {
  if (!currentManageIncidentId) return;

  const btn = document.getElementById("saveIncidentBtn");
  const sev = document.getElementById("modalSeverity")?.value;
  const status = document.getElementById("modalStatus")?.value;
  const comm = document.getElementById("modalComments")?.value;

  btn.disabled = true;
  btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Saving…`;

  try {
    // Update status
    const statusRes = await fetch(`${API}/incidents/${currentManageIncidentId}/status`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status })
    });

    // Add comment if provided
    if (comm && comm.trim()) {
      await fetch(`${API}/incidents/${currentManageIncidentId}/comment`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ comment: comm.trim() })
      });
    }

    if (statusRes.ok) {
      showToast("✅ Incident updated.", "success");
      document.getElementById("incidentModal").style.display = "none";
      await fetchIncidents(currentFilters);
    } else {
      showToast("❌ Failed to update incident.", "error");
    }
  } catch (err) {
    showToast("❌ Error: " + err.message, "error");
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<i class="fa-solid fa-floppy-disk"></i> Save Changes`;
  }
}

// ─── Model View ────────────────────────────────────────────────
async function loadModelView() {
  try {
    // Load metrics from system_health
    const hRes = await fetch(`${API}/system_health`);
    const hData = await hRes.json();
    const m = hData.model_metrics || {};

    setEl("activeModelVersion", `v${hData.model_version || "--"}`);
    setEl("metricAccuracy", m.accuracy != null ? `${(m.accuracy * 100).toFixed(1)}%` : "N/A");
    setEl("metricPrecision", m.precision != null ? `${(m.precision * 100).toFixed(1)}%` : "N/A");
    setEl("metricRecall", m.recall != null ? `${(m.recall * 100).toFixed(1)}%` : "N/A");
    setEl("metricF1", m.f1_score != null ? `${(m.f1_score * 100).toFixed(1)}%` : "N/A");

    // Load model versions
    const mRes = await fetch(`${API}/models`);
    const mData = await mRes.json();
    const list = document.getElementById("modelVersionsList");
    if (list && mData.data) {
      if (mData.data.length === 0) {
        list.innerHTML = `<div class="empty-state">No versions trained yet.</div>`;
        return;
      }
      list.innerHTML = mData.data.map(v => `
        <div class="version-item">
          <span class="version-tag">v${v.version}</span>
          <span class="version-meta">Acc: ${v.accuracy != null ? (v.accuracy * 100).toFixed(1) + "%" : "—"} | F1: ${v.f1_score != null ? (v.f1_score * 100).toFixed(1) + "%" : "—"}</span>
          <span class="version-meta">${v.trained_at ? new Date(v.trained_at).toLocaleDateString() : "—"}</span>
        </div>
      `).join("");
    }
  } catch (err) {
    console.error("Model view error:", err.message);
  }
}

// ─── Reports ───────────────────────────────────────────────────
async function loadSystemSummary() {
  const box = document.getElementById("systemSummaryContent");
  if (!box) return;
  box.innerHTML = `<div class="empty-state"><i class="fa-solid fa-spinner fa-spin"></i> Generating…</div>`;
  try {
    const res = await fetch(`${API}/reports/system_summary`);
    const data = await res.json();
    const rows = [
      ["Generated At", new Date(data.generated_at).toLocaleString()],
      ["Current CPU", data.current_cpu != null ? `${data.current_cpu.toFixed(1)}%` : "—"],
      ["Current Memory", data.current_memory != null ? `${data.current_memory.toFixed(1)}%` : "—"],
      ["Total Incidents", data.total_incidents],
      ["Ransomware Events", data.ransomware_incidents],
      ["Normal Events", data.normal_incidents],
      ["Blocked", data.prevention?.blocked],
      ["Failed Prevention", data.prevention?.failed],
      ["Escalated", data.prevention?.escalated],
      ["Prevention Rate", data.prevention?.success_rate != null ? `${(parseFloat(data.prevention.success_rate) * 100).toFixed(1)}%` : "—"],
      ["Open Incidents", data.incident_status?.open],
      ["Resolved Incidents", data.incident_status?.resolved],
      ["Model Version", data.model ? `v${data.model.version}` : "—"],
      ["Model Accuracy", data.model?.accuracy != null ? `${(data.model.accuracy * 100).toFixed(1)}%` : "—"],
    ];
    box.innerHTML = rows.map(([l, v]) =>
      `<div class="summary-row"><span class="s-label">${l}</span><span class="s-value">${v ?? "—"}</span></div>`
    ).join("");
  } catch (err) {
    box.innerHTML = `<div class="empty-state">Error loading summary.</div>`;
  }
}

async function exportCsv() {
  try {
    const res = await fetch(`${API}/reports/incidents/csv`);
    if (!res.ok) { showToast("Export failed.", "error"); return; }
    const blob = await res.blob();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `cortex_incidents_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    showToast("✅ CSV downloaded.", "success");
  } catch (err) {
    showToast("Export error: " + err.message, "error");
  }
}

async function exportJson() {
  try {
    const res = await fetch(`${API}/reports/system_summary`);
    const data = await res.json();
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `cortex_report_${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    showToast("✅ JSON exported.", "success");
  } catch (err) {
    showToast("Export error: " + err.message, "error");
  }
}

// ─── Auto-refresh ──────────────────────────────────────────────
let countdown = 5;

function startAutoRefresh() {
  const cdEl = document.getElementById("refreshCountdown");

  function tick() {
    countdown--;
    if (cdEl) cdEl.textContent = countdown;
    if (countdown <= 0) {
      countdown = 5;
      if (cdEl) cdEl.textContent = countdown;
      refreshAll();
    }
  }

  clearInterval(countdownInterval);
  countdownInterval = setInterval(tick, 1000);
}

async function refreshAll() {
  await Promise.all([
    fetchHealth(),
    fetchIncidents(currentFilters),
    fetchHealthStatus(),
  ]);
}

// ─── Helpers ───────────────────────────────────────────────────
function setEl(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function setStyle(id, prop, value) {
  const el = document.getElementById(id);
  if (el) el.style[prop] = value;
}

function escHtml(str) {
  return String(str || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function severityBadge(s) {
  const map = {
    CRITICAL: "badge-critical",
    HIGH: "badge-high",
    MEDIUM: "badge-medium",
    LOW: "badge-low",
    "": "badge-low",
  };
  const cls = map[(s || "").toUpperCase()] || "badge-low";
  return `<span class="badge ${cls}">${s || "LOW"}</span>`;
}

function statusBadge(s) {
  const map = {
    OPEN: "badge-open",
    INVESTIGATING: "badge-investigating",
    RESOLVED: "badge-resolved",
  };
  const cls = map[(s || "").toUpperCase()] || "badge-open";
  return `<span class="badge ${cls}">${s || "OPEN"}</span>`;
}

function preventionBadge(p) {
  const map = {
    BLOCKED: "badge-blocked",
    FAILED: "badge-failed",
    ESCALATED: "badge-escalated",
    NONE: "badge-none",
  };
  const cls = map[(p || "").toUpperCase()] || "badge-none";
  return `<span class="badge ${cls}">${p || "NONE"}</span>`;
}

// ─── Global fetch interceptor (auto redirect on 401) ───────────
const _origFetch = window.fetch;
window.fetch = async (...args) => {
  const res = await _origFetch(...args);
  if (res.status === 401) {
    window.location.href = "/login";
  }
  return res;
};

// ─── Init ──────────────────────────────────────────────────────
async function init() {
  const ok = await checkSession();
  if (!ok) return;

  setupNavigation();
  initCharts();

  // Initial data load
  await refreshAll();

  // Auto-refresh
  startAutoRefresh();

  // Button wiring
  const refreshBtn = document.getElementById("refreshBtn");
  if (refreshBtn) {
    refreshBtn.addEventListener("click", async () => {
      const icon = refreshBtn.querySelector("i");
      if (icon) icon.classList.add("fa-spin");
      countdown = 5;
      await refreshAll();
      if (icon) setTimeout(() => icon.classList.remove("fa-spin"), 500);
    });
  }

  // Incident filters
  document.getElementById("applyFiltersBtn")?.addEventListener("click", () => {
    currentFilters = {
      severity: document.getElementById("filterSeverity")?.value || "",
      status: document.getElementById("filterStatus")?.value || "",
      label: document.getElementById("filterLabel")?.value || "",
    };
    fetchIncidents(currentFilters);
  });

  document.getElementById("clearFiltersBtn")?.addEventListener("click", () => {
    currentFilters = {};
    ["filterSeverity", "filterStatus", "filterLabel"].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.value = "";
    });
    fetchIncidents();
  });

  // Modal
  document.getElementById("closeModalBtn")?.addEventListener("click", () => {
    document.getElementById("incidentModal").style.display = "none";
  });
  document.getElementById("cancelModalBtn")?.addEventListener("click", () => {
    document.getElementById("incidentModal").style.display = "none";
  });
  document.getElementById("saveIncidentBtn")?.addEventListener("click", saveIncident);

  // Close modal on overlay click
  document.getElementById("incidentModal")?.addEventListener("click", e => {
    if (e.target.id === "incidentModal") {
      document.getElementById("incidentModal").style.display = "none";
    }
  });

  // Reports
  document.getElementById("refreshSummaryBtn")?.addEventListener("click", loadSystemSummary);
  document.getElementById("exportCsvBtn")?.addEventListener("click", exportCsv);
  document.getElementById("exportJsonBtn")?.addEventListener("click", exportJson);

  // Logout
  document.getElementById("logoutBtn")?.addEventListener("click", () => {
    if (confirm("Confirm logout?")) handleLogout();
  });
}

document.addEventListener("DOMContentLoaded", init);
