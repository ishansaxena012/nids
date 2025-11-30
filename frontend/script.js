const API_BASE = "http://localhost:3000";
const REFRESH_INTERVAL_MS = 2000;

const $ = sel => document.querySelector(sel);
const $$ = sel => Array.from(document.querySelectorAll(sel));

function escapeHtml(s = "") {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/*
  Error handling + fetch helper
*/
const errorBanner = $("#error-banner");

function showError(msg) {
  if (!errorBanner) return;
  errorBanner.textContent = msg;
  errorBanner.hidden = false;
}

function clearError() {
  if (!errorBanner) return;
  errorBanner.hidden = true;
}

async function fetchJSON(url, opts = {}) {
  try {
    const res = await fetch(url, opts);
    if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);
    clearError();
    return await res.json();
  } catch (err) {
    console.error(`fetchJSON error for ${url}:`, err);
    showError("Backend not reachable or returned an error.");
    return null;
  }
}

/**
 * Map severity -> CSS tokens
 * Supports: critical, high, medium, low, unknown
 */
function severityClassTokens(sev) {
  const s = String(sev || "").toLowerCase().trim();

  if (!s) return ["severity", "unknown"];
  if (s === "critical" || s === "crit") return ["severity", "critical"];
  if (s === "high") return ["severity", "high"];
  if (s === "medium" || s === "med") return ["severity", "medium"];
  if (s === "low") return ["severity", "low"];

  return ["severity", "unknown"];
}

function formatSeverityLabel(sev) {
  const s = String(sev || "").toLowerCase().trim();
  if (s === "critical" || s === "crit") return "Critical";
  if (s === "high") return "High";
  if (s === "medium" || s === "med") return "Medium";
  if (s === "low") return "Low";
  return "Unknown";
}

const alertsTbody = $("#alerts-tbody") || $("#alerts-table tbody");
const rulesTbody = $("#rules-tbody") || $("#rules-table tbody");
const notificationsEl = $("#notifications");
const auditEl = $("#audit-logs");
const lastUpdateTimeEl = $("#last-update-time");
const refreshStatusEl = $("#refresh-status");
const pauseRefreshBtn = $("#pause-refresh");
const severitySummaryEl = $("#severity-summary");

const selectAllCheckbox = $("#select-all");
const bulkAckBtn = $("#bulk-ack");
const bulkExportBtn = $("#bulk-export");

const searchInput = $("#search");
const severityFilter = $("#severity-filter");
const ruleFilter = $("#rule-filter");
const resultCountEl = $("#result-count");

/*
  State
*/
let currentAlerts = [];
let currentRules = [];

let autoRefresh = true;
let refreshTimer = null;

let sortState = { field: "id", dir: "desc" };

/**
 * Build one alert row, including host (site) under description.
 */
function makeAlertRow(alert) {
  const id = escapeHtml(alert.id ?? "");
  const src = escapeHtml(alert.src_ip ?? alert.src ?? "");
  const dst = escapeHtml(alert.dst_ip ?? alert.dst ?? "");
  const proto = escapeHtml(alert.proto ?? "n/a");

  const severityRaw = alert.severity ?? "unknown";
  const severityLabel = formatSeverityLabel(severityRaw);
  const [sevBase, sevLevel] = severityClassTokens(severityRaw);

  const desc = escapeHtml(alert.desc ?? alert.description ?? "");
  const host = escapeHtml(alert.host ?? "");

  const tr = document.createElement("tr");
  tr.dataset.alertId = String(alert.id ?? "");

  // Optional: severity stripe on the left side of the row
  tr.classList.add(`sev-${sevLevel}`);

  tr.innerHTML = `
    <td class="col-id">
      <input type="checkbox" class="row-select" aria-label="Select alert ${id}" />
    </td>
    <td class="col-id">${id}</td>
    <td class="col-src">
      <button class="ip-copy btn" data-ip="${src}" title="Copy source IP">${src}</button>
    </td>
    <td class="col-dst">
      <button class="ip-copy btn" data-ip="${dst}" title="Copy destination IP">${dst}</button>
    </td>
    <td class="col-proto">${proto}</td>
    <td class="col-sev">
      <span class="badge ${sevBase} ${sevLevel}">${escapeHtml(severityLabel)}</span>
    </td>
    <td class="col-desc wrap">
      ${desc}
      ${host ? `<div class="small muted host-cell">${host}</div>` : ""}
    </td>
    <td class="col-actions">
      <button class="btn view-btn" data-id="${id}" aria-label="View alert ${id}">View</button>
      <button class="btn ack-btn" data-id="${id}" aria-label="Acknowledge alert ${id}">Ack</button>
    </td>
  `;
  return tr;
}


function applyTruncationTitles(container) {
  requestAnimationFrame(() => {
    const cells = container.querySelectorAll("td");
    cells.forEach(td => {
      const txt = td.textContent?.trim() ?? "";
      if (!txt) {
        td.removeAttribute("title");
        return;
      }
      if (td.scrollWidth > td.clientWidth + 2) {
        td.setAttribute("title", txt);
      } else {
        td.removeAttribute("title");
      }
    });
  });
}

/*
   Data loaders
*/
async function loadAlerts() {
  const data = await fetchJSON(`${API_BASE}/api/alerts`);
  if (!Array.isArray(data)) {
    console.warn("loadAlerts: unexpected data", data);
    return;
  }
  currentAlerts = data;

  updateSeveritySummary();
  renderAlerts();
  updateResultCount();
  updateLastUpdateTime();
}

/**
 * Match alert against current search + filters.
 * Now also searches in alert.host.
 */
function matchesFilters(alert) {
  const q = (searchInput?.value || "").toLowerCase().trim();
  const sevFilterVal = (severityFilter?.value || "").toLowerCase();
  const ruleFilterVal = (ruleFilter?.value || "").toLowerCase();

  if (q) {
    const hay = `${alert.src_ip ?? alert.src ?? ""} \
${alert.dst_ip ?? alert.dst ?? ""} \
${alert.desc ?? alert.description ?? ""} \
${alert.proto ?? ""} \
${alert.id ?? ""} \
${alert.host ?? ""}`.toLowerCase();
    if (!hay.includes(q)) return false;
  }

  if (sevFilterVal) {
    const [, alertSevLevel] = severityClassTokens(alert.severity);
    if (alertSevLevel !== sevFilterVal) return false;
  }

  if (ruleFilterVal) {
    const ruleName = (alert.rule_name ?? alert.rule ?? "").toString().toLowerCase();
    const ruleId = (alert.rule_id ?? "").toString().toLowerCase();
    if (!ruleName.includes(ruleFilterVal) && !ruleId.includes(ruleFilterVal)) return false;
  }

  return true;
}


function renderAlerts() {
  if (!alertsTbody) return;

  const visible = currentAlerts.filter(matchesFilters);
  alertsTbody.innerHTML = "";

  const frag = document.createDocumentFragment();
  for (const a of visible) {
    frag.appendChild(makeAlertRow(a));
  }
  alertsTbody.appendChild(frag);

  applyTruncationTitles(alertsTbody);
  updateSelectAllState();
}

async function loadRules() {
  const data = await fetchJSON(`${API_BASE}/api/rules`);
  if (!Array.isArray(data)) {
    console.warn("loadRules: unexpected", data);
    return;
  }
  currentRules = data;

  if (rulesTbody) {
    rulesTbody.innerHTML = data
      .map(r => {
        const id = escapeHtml(r.id ?? "");
        const name = escapeHtml(r.name ?? "");
        const pattern = escapeHtml(r.pattern ?? "");
        const enabled = r.enabled ? "Yes" : "No";
        return `<tr data-rule-id="${id}">
        <td class="col-id">${id}</td>
        <td class="col-name">${name}</td>
        <td class="col-pattern wrap">${pattern}</td>
        <td class="col-enabled">${enabled}</td>
      </tr>`;
      })
      .join("");
    applyTruncationTitles(rulesTbody);
  }

  if (ruleFilter) {
    const cur = ruleFilter.value || "";
    ruleFilter.innerHTML =
      `<option value="">All rules</option>` +
      data
        .map(
          r =>
            `<option value="${escapeHtml(r.name ?? r.id ?? "")}">${escapeHtml(
              r.name ?? r.id ?? ""
            )}</option>`
        )
        .join("");
    ruleFilter.value = cur;
  }
}

async function loadNotifications() {
  const data = await fetchJSON(`${API_BASE}/api/notifications/pending`);
  if (!Array.isArray(data)) {
    console.warn("loadNotifications: unexpected", data);
    return;
  }
  if (!notificationsEl) return;
  notificationsEl.innerHTML = data
    .map(n => {
      const t = escapeHtml(n.event_type ?? "event");
      const payload = escapeHtml(JSON.stringify(n.payload ?? {}, null, 2));
      const when = n.created_at ? new Date(n.created_at).toLocaleString() : "";
      return `<div class="notify-item"><strong>${t}</strong> <span class="small muted">${when}</span><pre style="white-space:pre-wrap; margin-top:8px;">${payload}</pre></div>`;
    })
    .join("");
  applyTruncationTitles(notificationsEl);
}

async function loadAudit() {
  const data = await fetchJSON(`${API_BASE}/api/audit`);
  if (!Array.isArray(data)) {
    console.warn("loadAudit: unexpected", data);
    return;
  }
  if (!auditEl) return;
  auditEl.innerHTML = data
    .map(l => {
      const action = escapeHtml(l.action ?? "");
      const target = `${escapeHtml(l.target_type ?? "")}#${escapeHtml(
        l.target_id ?? ""
      )}`;
      const ts = l.ts ? new Date(l.ts).toLocaleString() : "";
      return `<div class="audit-item"><strong>${action}</strong> → ${target}<br/><small class="muted">${ts}</small></div>`;
    })
    .join("");
  applyTruncationTitles(auditEl);
}

/*
   Filtering & summary
*/
function matchesFilters(alert) {
  const q = (searchInput?.value || "").toLowerCase().trim();
  const sevFilterVal = (severityFilter?.value || "").toLowerCase();
  const ruleFilterVal = (ruleFilter?.value || "").toLowerCase();

  if (q) {
    const hay = `${alert.src_ip ?? alert.src ?? ""} \
${alert.dst_ip ?? alert.dst ?? ""} \
${alert.desc ?? alert.description ?? ""} \
${alert.proto ?? ""} \
${alert.id ?? ""} \
${alert.host ?? ""}`.toLowerCase();
    if (!hay.includes(q)) return false;
  }

  if (sevFilterVal) {
    if ((alert.severity ?? "").toLowerCase() !== sevFilterVal) return false;
  }

  if (ruleFilterVal) {
    const ruleName = (alert.rule_name ?? alert.rule ?? "").toString().toLowerCase();
    const ruleId = (alert.rule_id ?? "").toString().toLowerCase();
    if (!ruleName.includes(ruleFilterVal) && !ruleId.includes(ruleFilterVal)) return false;
  }

  return true;
}

function updateSeveritySummary() {
  if (!severitySummaryEl) return;
  const counts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };

  currentAlerts.forEach(a => {
    const s = (a.severity || "unknown").toLowerCase();
    if (counts[s] === undefined) counts.unknown++;
    else counts[s]++;
  });

  severitySummaryEl.innerHTML = `
    <span class="summary-pill critical">Critical: ${counts.critical}</span>
    <span class="summary-pill high">High: ${counts.high}</span>
    <span class="summary-pill medium">Med: ${counts.medium}</span>
    <span class="summary-pill low">Low: ${counts.low}</span>
    <span class="summary-pill unknown">Other: ${counts.unknown}</span>
  `;
}

/*
   Sorting & rendering
*/
function compareAlerts(a, b) {
  const { field, dir } = sortState;
  let va, vb;

  switch (field) {
    case "severity": {
      const order = ["critical", "high", "medium", "low", "unknown"];
      const sa = (a.severity || "unknown").toLowerCase();
      const sb = (b.severity || "unknown").toLowerCase();
      va = order.indexOf(sa);
      vb = order.indexOf(sb);
      break;
    }
    case "id":
    default:
      va = Number(a.id) || 0;
      vb = Number(b.id) || 0;
  }

  const diff = va - vb;
  return dir === "asc" ? diff : -diff;
}

function renderAlerts() {
  if (!alertsTbody) return;

  const visible = currentAlerts.filter(matchesFilters).sort(compareAlerts);
  alertsTbody.innerHTML = "";

  const frag = document.createDocumentFragment();
  for (const a of visible) {
    frag.appendChild(makeAlertRow(a));
  }
  alertsTbody.appendChild(frag);

  applyTruncationTitles(alertsTbody);
  updateSelectAllState();
}

/*
   Controls & interactions
*/
function updateResultCount() {
  if (!resultCountEl) return;
  const visibleCount = currentAlerts.filter(matchesFilters).length;
  resultCountEl.textContent = `${visibleCount} alert${visibleCount === 1 ? "" : "s"}`;
}

function updateLastUpdateTime() {
  if (!lastUpdateTimeEl) return;
  lastUpdateTimeEl.textContent = new Date().toLocaleString();
}

function updateSelectAllState() {
  if (!selectAllCheckbox || !alertsTbody) return;
  const checkboxes = Array.from(alertsTbody.querySelectorAll(".row-select"));
  if (checkboxes.length === 0) {
    selectAllCheckbox.checked = false;
    selectAllCheckbox.indeterminate = false;
    return;
  }
  const checked = checkboxes.filter(cb => cb.checked).length;
  selectAllCheckbox.checked = checked === checkboxes.length;
  selectAllCheckbox.indeterminate = checked > 0 && checked < checkboxes.length;
}

async function bulkAcknowledgeSelected() {
  if (!alertsTbody) return;
  const selected = Array.from(alertsTbody.querySelectorAll(".row-select:checked"))
    .map(cb => cb.closest("tr")?.dataset.alertId)
    .filter(Boolean);

  if (selected.length === 0) {
    alert("No alerts selected");
    return;
  }

  appendAudit(`Bulk acknowledge: ${selected.join(",")}`);

  try {
    const res = await fetch(`${API_BASE}/api/alerts/ack`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ids: selected })
    });
    if (!res.ok) throw new Error(`ACK failed ${res.status}`);
    const json = await res.json();
    console.info("Bulk ack result:", json);
    appendNotification(`Acknowledged ${selected.length} alerts`);
    await loadAlerts();
  } catch (err) {
    console.warn("bulk ack failed, falling back to local update", err);
    appendNotification(`(Local) acknowledged ${selected.length} alerts`);
    selected.forEach(id => {
      const tr = alertsTbody.querySelector(`tr[data-alert-id="${id}"]`);
      if (tr) tr.style.opacity = "0.6";
    });
  }
}

/**
 * CSV export — includes host column
 */
function exportSelectedCSV() {
  if (!alertsTbody) return;
  const selectedRows = Array.from(
    alertsTbody.querySelectorAll(".row-select:checked")
  ).map(cb => cb.closest("tr"));

  const rows = (selectedRows.length ? selectedRows : Array.from(alertsTbody.querySelectorAll("tr")))
    .map(tr => {
      const id =
        tr.querySelector(".col-id:nth-of-type(2)")?.textContent?.trim() ??
        tr.dataset.alertId ??
        "";
      const src = tr.querySelector(".col-src")?.textContent?.trim() ?? "";
      const dst = tr.querySelector(".col-dst")?.textContent?.trim() ?? "";
      const proto = tr.querySelector(".col-proto")?.textContent?.trim() ?? "";
      const sev = tr.querySelector(".col-sev")?.textContent?.trim() ?? "";
      const desc = tr.querySelector(".col-desc")?.textContent?.trim() ?? "";

      const alertObj = currentAlerts.find(a => String(a.id) === String(id));
      const host = alertObj?.host ?? "";

      return [id, src, dst, proto, sev, desc, host];
    });

  const csv = [
    ["id", "src", "dst", "proto", "severity", "description", "host"],
    ...rows
  ]
    .map(r =>
      r
        .map(cell => `"${String(cell ?? "").replace(/"/g, '""')}"`)
        .join(",")
    )
    .join("\n");

  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `alerts-export-${Date.now()}.csv`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  appendNotification(`Exported ${rows.length} alerts`);
}

async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    appendNotification(`Copied ${text}`);
  } catch (err) {
    console.warn("copy failed", err);
    alert(`Copy failed: ${text}`);
  }
}

function appendNotification(msg) {
  if (!notificationsEl) return;
  const el = document.createElement("div");
  el.className = "notify-item";
  el.innerHTML = `<strong>Info</strong> <span class="small muted">${new Date().toLocaleString()}</span><div style="margin-top:6px">${escapeHtml(
    msg
  )}</div>`;
  notificationsEl.prepend(el);
  applyTruncationTitles(notificationsEl);
}

function appendAudit(msg) {
  if (!auditEl) return;
  const el = document.createElement("div");
  el.className = "audit-item";
  el.innerHTML = `<strong>Audit</strong> <small class="muted">${new Date().toLocaleString()}</small><div style="margin-top:6px">${escapeHtml(
    msg
  )}</div>`;
  auditEl.prepend(el);
  applyTruncationTitles(auditEl);
}

/*
   Event delegation for table actions
*/
function onTableClicked(e) {
  const viewBtn = e.target.closest(".view-btn");
  const ackBtn = e.target.closest(".ack-btn");
  const ipCopy = e.target.closest(".ip-copy");
  if (viewBtn) {
    const id = viewBtn.dataset.id;
    const alertObj = currentAlerts.find(a => String(a.id) === String(id));
    if (alertObj) {
      showAlertModal(alertObj);
    } else {
      appendNotification(`Alert ${id} not found`);
    }
    return;
  }
  if (ackBtn) {
    const id = ackBtn.dataset.id;
    ackSingle(id);
    return;
  }
  if (ipCopy) {
    const ip = ipCopy.dataset.ip;
    if (ip) copyToClipboard(ip);
    return;
  }
}

async function ackSingle(id) {
  appendAudit(`Acknowledge ${id}`);
  try {
    const r = await fetch(
      `${API_BASE}/api/alerts/${encodeURIComponent(id)}/ack`,
      { method: "POST" }
    );
    if (!r.ok) throw new Error(`ack failed ${r.status}`);
    appendNotification(`Acknowledged ${id}`);
    await loadAlerts();
  } catch (err) {
    console.warn("ack failed (local fallback)", err);
    appendNotification(`(Local) Acknowledged ${id}`);
    const tr = alertsTbody.querySelector(`tr[data-alert-id="${id}"]`);
    if (tr) tr.style.opacity = "0.6";
  }
}

/**
 * Show alert modal.
 */
function showAlertModal(alertObj) {
  const backdrop = $("#modal-backdrop");
  const body = $("#modal-body");
  if (!backdrop || !body) {
    console.warn("Modal elements missing");
    return;
  }

  const time =
    alertObj.ts ||
    alertObj.created_at ||
    "";
  const severityRaw = alertObj.severity ?? "";
  const severityLabel = formatSeverityLabel(severityRaw);
  const [sevBase, sevLevel] = severityClassTokens(severityRaw);
  const host = alertObj.host ?? "";

  const severityBadge = `<span class="badge ${sevBase} ${sevLevel}">${escapeHtml(severityLabel)}</span>`;

  body.innerHTML = `
    <div><strong>ID:</strong> ${escapeHtml(String(alertObj.id ?? ""))}</div>
    <div><strong>Severity:</strong> ${severityBadge}</div>
    <div><strong>Time:</strong> ${escapeHtml(String(time))}</div>
    <div><strong>Src:</strong> ${escapeHtml(alertObj.src_ip ?? alertObj.src ?? "")}</div>
    <div><strong>Dst:</strong> ${escapeHtml(alertObj.dst_ip ?? alertObj.dst ?? "")}</div>
    <div><strong>Proto:</strong> ${escapeHtml(alertObj.proto ?? "")}</div>
    <div><strong>Host:</strong> ${escapeHtml(host)}</div>
    <div style="margin-top:8px"><strong>Description</strong><pre style="white-space:pre-wrap; margin-top:6px;">${escapeHtml(
      alertObj.desc ?? alertObj.description ?? ""
    )}</pre></div>
    <div style="margin-top:8px"><strong>Raw</strong><pre style="white-space:pre-wrap; margin-top:6px;">${escapeHtml(
      JSON.stringify(alertObj, null, 2)
    )}</pre></div>
  `;
  backdrop.setAttribute("aria-hidden", "false");

  const close = $("#modal-close");
  const close2 = $("#modal-close-2");
  const ackBtn = $("#modal-ack");
  const previouslyFocused = document.activeElement;

  ackBtn?.focus();

  function cleanup() {
    backdrop.setAttribute("aria-hidden", "true");
    close?.removeEventListener("click", cleanup);
    close2?.removeEventListener("click", cleanup);
    ackBtn?.removeEventListener("click", onAck);
    previouslyFocused?.focus();
  }
  function onAck() {
    ackSingle(alertObj.id);
    cleanup();
  }
  close?.addEventListener("click", cleanup);
  close2?.addEventListener("click", cleanup);
  ackBtn?.addEventListener("click", onAck);
}

/*
   Auto-refresh controls
*/
function setRefreshState(enabled) {
  autoRefresh = enabled;
  if (refreshStatusEl) {
    refreshStatusEl.textContent = enabled ? "Auto-refreshing…" : "Paused";
  }
  if (!enabled && refreshTimer) {
    clearTimeout(refreshTimer);
    refreshTimer = null;
  } else if (enabled && !refreshTimer) {
    scheduleRefresh();
  }
}

function scheduleRefresh() {
  if (!autoRefresh) return;
  refreshTimer = setTimeout(async () => {
    await loadAll();
    scheduleRefresh();
  }, REFRESH_INTERVAL_MS);
}

/*
   Wiring up DOM events
*/
function wireUp() {
  const alertsWrapper =
    $("#alerts-table-wrapper") || $("#alerts-table").parentElement;
  alertsWrapper?.addEventListener("click", onTableClicked);

  selectAllCheckbox?.addEventListener("change", e => {
    const checked = e.target.checked;
    Array.from(alertsTbody.querySelectorAll(".row-select")).forEach(cb => {
      cb.checked = checked;
    });
    updateSelectAllState();
  });

  alertsTbody?.addEventListener("change", e => {
    if (e.target.matches(".row-select")) updateSelectAllState();
  });

  bulkAckBtn?.addEventListener("click", bulkAcknowledgeSelected);
  bulkExportBtn?.addEventListener("click", exportSelectedCSV);

  const debouncedRender = debounce(() => {
    renderAlerts();
    updateResultCount();
  }, 180);
  searchInput?.addEventListener("input", debouncedRender);
  severityFilter?.addEventListener("change", () => {
    renderAlerts();
    updateResultCount();
  });
  ruleFilter?.addEventListener("change", () => {
    renderAlerts();
    updateResultCount();
  });

  // sortable headers
  $$("#alerts-table thead th.sortable").forEach(th => {
    th.addEventListener("click", () => {
      const field = th.dataset.sort;
      if (!field) return;
      if (sortState.field === field) {
        sortState.dir = sortState.dir === "asc" ? "desc" : "asc";
      } else {
        sortState = { field, dir: "asc" };
      }
      renderAlerts();
      updateResultCount();
    });
  });

  pauseRefreshBtn?.addEventListener("click", () => {
    setRefreshState(!autoRefresh);
    pauseRefreshBtn.textContent = autoRefresh ? "Pause" : "Resume";
  });

  document.addEventListener("keydown", e => {
    if (e.key === "Escape") {
      $("#modal-backdrop")?.setAttribute("aria-hidden", "true");
      $("#rule-modal-backdrop")?.setAttribute("aria-hidden", "true");
    }
  });
}

function debounce(fn, wait = 150) {
  let t;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), wait);
  };
}

async function loadAll() {
  try {
    await Promise.all([
      loadAlerts(),
      loadRules(),
      loadNotifications(),
      loadAudit()
    ]);
  } catch (err) {
    console.error("loadAll error", err);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  wireUp();
  loadAll();
  scheduleRefresh();
});
