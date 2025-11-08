const API_BASE = "http://localhost:3000";
const REFRESH_INTERVAL_MS = 10000; 

const $ = sel => document.querySelector(sel);
const $$ = sel => Array.from(document.querySelectorAll(sel));

function escapeHtml(s = '') {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

async function fetchJSON(url, opts = {}) {
  try {
    const res = await fetch(url, opts);
    if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);
    return await res.json();
  } catch (err) {
    console.error(`fetchJSON error for ${url}:`, err);
    return null;
  }
}

function severityClassTokens(sev) {
  if (!sev) return ['severity', 'unknown'];
  const s = String(sev).toLowerCase();
  if (s === 'high') return ['severity', 'high'];
  if (s === 'medium') return ['severity', 'medium'];
  if (s === 'low') return ['severity', 'low'];
  return ['severity', 'unknown'];
}

const alertsTbody = $('#alerts-tbody') || $('#alerts-table tbody'); 
const rulesTbody = $('#rules-tbody') || $('#rules-table tbody');
const notificationsEl = $('#notifications');
const auditEl = $('#audit-logs');
const lastUpdateTimeEl = $('#last-update-time');

const selectAllCheckbox = $('#select-all');
const bulkAckBtn = $('#bulk-ack');
const bulkExportBtn = $('#bulk-export');

const searchInput = $('#search');
const severityFilter = $('#severity-filter');
const ruleFilter = $('#rule-filter');
const resultCountEl = $('#result-count');

let currentAlerts = [];   
let currentRules = [];   


function makeAlertRow(alert) {
  const id = escapeHtml(alert.id ?? '');
  const src = escapeHtml(alert.src_ip ?? alert.src ?? '');
  const dst = escapeHtml(alert.dst_ip ?? alert.dst ?? '');
  const proto = escapeHtml(alert.proto ?? 'n/a');
  const severity = escapeHtml(alert.severity ?? 'n/a');
  const desc = escapeHtml(alert.desc ?? alert.description ?? '');

  const [sevBase, sevLevel] = severityClassTokens(severity);

  // Row with a leading checkbox
  const tr = document.createElement('tr');
  tr.dataset.alertId = String(alert.id ?? '');
  tr.innerHTML = `
    <td class="col-id"><input type="checkbox" class="row-select" aria-label="Select alert ${id}" /></td>
    <td class="col-id">${id}</td>
    <td class="col-src"><button class="ip-copy btn" data-ip="${src}" title="Copy source IP">${src}</button></td>
    <td class="col-dst"><button class="ip-copy btn" data-ip="${dst}" title="Copy destination IP">${dst}</button></td>
    <td class="col-proto">${proto}</td>
    <td class="col-sev"><span class="${sevBase} ${sevLevel}">${severity}</span></td>
    <td class="col-desc wrap">${desc}</td>
    <td class="col-actions">
      <button class="btn view-btn" data-id="${id}" aria-label="View alert ${id}">View</button>
      <button class="btn ack-btn" data-id="${id}" aria-label="Acknowledge alert ${id}">Ack</button>
    </td>
  `;
  return tr;
}

function applyTruncationTitles(container) {
  // Add title attributes to cells that overflow so user can hover to see full text
  // Run after DOM insertion (use requestAnimationFrame)
  requestAnimationFrame(() => {
    const cells = container.querySelectorAll('td');
    cells.forEach(td => {
      const txt = td.textContent?.trim() ?? '';
      if (!txt) { td.removeAttribute('title'); return; }

      // If the content is bigger than the box, set title
      if (td.scrollWidth > td.clientWidth + 2) {
        td.setAttribute('title', txt);
      } else {
        td.removeAttribute('title');
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
    console.warn('loadAlerts: unexpected data', data);
    return;
  }
  currentAlerts = data;

  renderAlerts();
  updateResultCount();
  updateLastUpdateTime();
}

function matchesFilters(alert) {
  const q = (searchInput?.value || '').toLowerCase().trim();
  const sevFilter = (severityFilter?.value || '').toLowerCase();
  const ruleFilterVal = (ruleFilter?.value || '').toLowerCase();

  // search in src/dst/desc/proto/id
  if (q) {
    const hay = `${alert.src_ip ?? alert.src ?? ''} ${alert.dst_ip ?? alert.dst ?? ''} ${alert.desc ?? alert.description ?? ''} ${alert.proto ?? ''} ${alert.id ?? ''}`.toLowerCase();
    if (!hay.includes(q)) return false;
  }
  if (sevFilter) {
    if ((alert.severity ?? '').toLowerCase() !== sevFilter) return false;
  }
  if (ruleFilterVal) {
    // some alert objects may include rule_name or rule_id
    const ruleName = (alert.rule_name ?? alert.rule ?? '').toString().toLowerCase();
    const ruleId = (alert.rule_id ?? '').toString().toLowerCase();
    if (!ruleName.includes(ruleFilterVal) && !ruleId.includes(ruleFilterVal)) return false;
  }
  return true;
}

function renderAlerts() {
  if (!alertsTbody) return;
  // Filter the cached alerts by current controls
  const visible = currentAlerts.filter(matchesFilters);
  alertsTbody.innerHTML = '';

  // Build rows
  const frag = document.createDocumentFragment();
  for (const a of visible) {
    frag.appendChild(makeAlertRow(a));
  }
  alertsTbody.appendChild(frag);

  // Hooks: truncation titles, row buttons
  applyTruncationTitles(alertsTbody);

  // Wire up per-row buttons (delegation is used later too)
  // update "select-all" checkbox state
  updateSelectAllState();
}

async function loadRules() {
  const data = await fetchJSON(`${API_BASE}/api/rules`);
  if (!Array.isArray(data)) {
    console.warn('loadRules: unexpected', data);
    return;
  }
  currentRules = data;

  if (rulesTbody) {
    rulesTbody.innerHTML = data.map(r => {
      const id = escapeHtml(r.id ?? '');
      const name = escapeHtml(r.name ?? '');
      const pattern = escapeHtml(r.pattern ?? '');
      const enabled = r.enabled ? 'Yes' : 'No';
      return `<tr data-rule-id="${id}">
        <td class="col-id">${id}</td>
        <td class="col-name">${name}</td>
        <td class="col-pattern wrap">${pattern}</td>
        <td class="col-enabled">${enabled}</td>
      </tr>`;
    }).join('');
    applyTruncationTitles(rulesTbody);
  }

  // Populate rule filter select (if present)
  if (ruleFilter) {
    const cur = ruleFilter.value || '';
    ruleFilter.innerHTML = `<option value="">All rules</option>` +
      data.map(r => `<option value="${escapeHtml(r.name ?? r.id ?? '')}">${escapeHtml(r.name ?? r.id ?? '')}</option>`).join('');
    ruleFilter.value = cur;
  }
}

async function loadNotifications() {
  const data = await fetchJSON(`${API_BASE}/api/notifications/pending`);
  if (!Array.isArray(data)) {
    console.warn('loadNotifications: unexpected', data);
    return;
  }
  if (!notificationsEl) return;
  notificationsEl.innerHTML = data.map(n => {
    const t = escapeHtml(n.event_type ?? 'event');
    const payload = escapeHtml(JSON.stringify(n.payload ?? {}, null, 2));
    const when = n.created_at ? new Date(n.created_at).toLocaleString() : '';
    return `<div class="notify-item"><strong>${t}</strong> <span class="small muted">${when}</span><pre style="white-space:pre-wrap; margin-top:8px;">${payload}</pre></div>`;
  }).join('');
  applyTruncationTitles(notificationsEl);
}

async function loadAudit() {
  const data = await fetchJSON(`${API_BASE}/api/audit`);
  if (!Array.isArray(data)) {
    console.warn('loadAudit: unexpected', data);
    return;
  }
  if (!auditEl) return;
  auditEl.innerHTML = data.map(l => {
    const action = escapeHtml(l.action ?? '');
    const target = `${escapeHtml(l.target_type ?? '')}#${escapeHtml(l.target_id ?? '')}`;
    const ts = l.ts ? new Date(l.ts).toLocaleString() : '';
    return `<div class="audit-item"><strong>${action}</strong> → ${target}<br/><small class="muted">${ts}</small></div>`;
  }).join('');
  applyTruncationTitles(auditEl);
}

/* 
   Controls & interactions
 */
function updateResultCount() {
  if (!resultCountEl) return;
  const visibleCount = currentAlerts.filter(matchesFilters).length;
  resultCountEl.textContent = `${visibleCount} alert${visibleCount === 1 ? '' : 's'}`;
}

function updateLastUpdateTime() {
  if (!lastUpdateTimeEl) return;
  lastUpdateTimeEl.textContent = new Date().toLocaleString();
}

/* Select/deselect all rows */
function updateSelectAllState() {
  if (!selectAllCheckbox || !alertsTbody) return;
  const checkboxes = Array.from(alertsTbody.querySelectorAll('.row-select'));
  if (checkboxes.length === 0) { selectAllCheckbox.checked = false; selectAllCheckbox.indeterminate = false; return; }
  const checked = checkboxes.filter(cb => cb.checked).length;
  selectAllCheckbox.checked = checked === checkboxes.length;
  selectAllCheckbox.indeterminate = checked > 0 && checked < checkboxes.length;
}

/* Bulk acknowledge selected alerts — POST to API if available */
async function bulkAcknowledgeSelected() {
  if (!alertsTbody) return;
  const selected = Array.from(alertsTbody.querySelectorAll('.row-select:checked'))
    .map(cb => cb.closest('tr')?.dataset.alertId)
    .filter(Boolean);

  if (selected.length === 0) {
    alert('No alerts selected');
    return;
  }

  appendAudit(`Bulk acknowledge: ${selected.join(',')}`);

  try {
    const res = await fetch(`${API_BASE}/api/alerts/ack`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ ids: selected })
    });
    if (!res.ok) throw new Error(`ACK failed ${res.status}`);
    const json = await res.json();
    console.info('Bulk ack result:', json);
    appendNotification(`Acknowledged ${selected.length} alerts`);
    await loadAlerts();
  } catch (err) {
    console.warn('bulk ack failed, falling back to local update', err);
    appendNotification(`(Local) acknowledged ${selected.length} alerts`);
    selected.forEach(id => {
      const tr = alertsTbody.querySelector(`tr[data-alert-id="${id}"]`);
      if (tr) tr.style.opacity = '0.6';
    });
  }
}

function exportSelectedCSV() {
  if (!alertsTbody) return;
  const selectedRows = Array.from(alertsTbody.querySelectorAll('.row-select:checked'))
    .map(cb => cb.closest('tr'));
  const rows = (selectedRows.length ? selectedRows : Array.from(alertsTbody.querySelectorAll('tr')))
    .map(tr => {
      const id = tr.querySelector('.col-id:nth-of-type(2)')?.textContent?.trim() ?? tr.dataset.alertId ?? '';
      const src = tr.querySelector('.col-src')?.textContent?.trim() ?? '';
      const dst = tr.querySelector('.col-dst')?.textContent?.trim() ?? '';
      const proto = tr.querySelector('.col-proto')?.textContent?.trim() ?? '';
      const sev = tr.querySelector('.col-sev')?.textContent?.trim() ?? '';
      const desc = tr.querySelector('.col-desc')?.textContent?.trim() ?? '';
      return [id, src, dst, proto, sev, desc];
    });

  const csv = [
    ['id','src','dst','proto','severity','description'],
    ...rows
  ].map(r => r.map(cell => `"${String(cell ?? '').replace(/"/g,'""')}"`).join(',')).join('\n');

  const blob = new Blob([csv], {type:'text/csv;charset=utf-8;'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
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
    console.warn('copy failed', err);
    alert(`Copy failed: ${text}`);
  }
}

function appendNotification(msg) {
  if (!notificationsEl) return;
  const el = document.createElement('div');
  el.className = 'notify-item';
  el.innerHTML = `<strong>Info</strong> <span class="small muted">${new Date().toLocaleString()}</span><div style="margin-top:6px">${escapeHtml(msg)}</div>`;
  notificationsEl.prepend(el);
  applyTruncationTitles(notificationsEl);
}

function appendAudit(msg) {
  if (!auditEl) return;
  const el = document.createElement('div');
  el.className = 'audit-item';
  el.innerHTML = `<strong>Audit</strong> <small class="muted">${new Date().toLocaleString()}</small><div style="margin-top:6px">${escapeHtml(msg)}</div>`;
  auditEl.prepend(el);
  applyTruncationTitles(auditEl);
}

/* 
   Event delegation for table actions
*/
function onTableClicked(e) {
  const viewBtn = e.target.closest('.view-btn');
  const ackBtn = e.target.closest('.ack-btn');
  const ipCopy = e.target.closest('.ip-copy');
  if (viewBtn) {
    const id = viewBtn.dataset.id;
    // find alert and show modal (modal handling is left to your modal logic)
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
    // small optimistic ack
    ackSingle(id);
    return;
  }
  if (ipCopy) {
    const ip = ipCopy.dataset.ip;
    if (ip) copyToClipboard(ip);
    return;
  }
}

/* Acknowledge a single alert (POST to API if available) */
async function ackSingle(id) {
  appendAudit(`Acknowledge ${id}`);
  try {
    const r = await fetch(`${API_BASE}/api/alerts/${encodeURIComponent(id)}/ack`, { method: 'POST' });
    if (!r.ok) throw new Error(`ack failed ${r.status}`);
    appendNotification(`Acknowledged ${id}`);
    await loadAlerts();
  } catch (err) {
    console.warn('ack failed (local fallback)', err);
    appendNotification(`(Local) Acknowledged ${id}`);
    const tr = alertsTbody.querySelector(`tr[data-alert-id="${id}"]`);
    if (tr) tr.style.opacity = '0.6';
  }
}

/* Show alert modal (fill modal template) */
function showAlertModal(alertObj) {
  const backdrop = $('#modal-backdrop');
  const body = $('#modal-body');
  if (!backdrop || !body) {
    console.warn('Modal elements missing');
    return;
  }
  body.innerHTML = `
    <div><strong>ID:</strong> ${escapeHtml(String(alertObj.id ?? ''))}</div>
    <div><strong>Src:</strong> ${escapeHtml(alertObj.src_ip ?? alertObj.src ?? '')}</div>
    <div><strong>Dst:</strong> ${escapeHtml(alertObj.dst_ip ?? alertObj.dst ?? '')}</div>
    <div><strong>Proto:</strong> ${escapeHtml(alertObj.proto ?? '')}</div>
    <div style="margin-top:8px"><strong>Description</strong><pre style="white-space:pre-wrap; margin-top:6px;">${escapeHtml(alertObj.desc ?? alertObj.description ?? '')}</pre></div>
    <div style="margin-top:8px"><strong>Raw</strong><pre style="white-space:pre-wrap; margin-top:6px;">${escapeHtml(JSON.stringify(alertObj, null, 2))}</pre></div>
  `;
  backdrop.setAttribute('aria-hidden', 'false');
  // focus management handled in your modal code; set basic handler:
  const close = $('#modal-close');
  const close2 = $('#modal-close-2');
  const ackBtn = $('#modal-ack');
  function cleanup() {
    backdrop.setAttribute('aria-hidden', 'true');
    close?.removeEventListener('click', cleanup);
    close2?.removeEventListener('click', cleanup);
    ackBtn?.removeEventListener('click', onAck);
  }
  function onAck() {
    ackSingle(alertObj.id);
    cleanup();
  }
  close?.addEventListener('click', cleanup);
  close2?.addEventListener('click', cleanup);
  ackBtn?.addEventListener('click', onAck);
}

/* 
   Wiring up DOM events
*/
function wireUp() {
  // Delegated clicks on alerts table wrapper
  const alertsWrapper = $('#alerts-table-wrapper') || $('#alerts-table').parentElement;
  alertsWrapper?.addEventListener('click', onTableClicked);

  // Select all checkbox
  selectAllCheckbox?.addEventListener('change', e => {
    const checked = e.target.checked;
    Array.from(alertsTbody.querySelectorAll('.row-select')).forEach(cb => { cb.checked = checked; });
    updateSelectAllState();
  });

  // Per-row checkbox change updates overall select state
  alertsTbody?.addEventListener('change', e => {
    if (e.target.matches('.row-select')) updateSelectAllState();
  });

  // Bulk ack/export
  bulkAckBtn?.addEventListener('click', bulkAcknowledgeSelected);
  bulkExportBtn?.addEventListener('click', exportSelectedCSV);

  // search/filter -> re-render
  const debouncedRender = debounce(() => { renderAlerts(); updateResultCount(); }, 180);
  searchInput?.addEventListener('input', debouncedRender);
  severityFilter?.addEventListener('change', () => { renderAlerts(); updateResultCount(); });
  ruleFilter?.addEventListener('change', () => { renderAlerts(); updateResultCount(); });

  // close modals on ESC
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      $('#modal-backdrop')?.setAttribute('aria-hidden', 'true');
      $('#rule-modal-backdrop')?.setAttribute('aria-hidden', 'true');
    }
  });

  // simple delegation for view/ack buttons (alternate route)
  // handled already by onTableClicked via alertsWrapper click listener
}

function debounce(fn, wait=150){
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(()=>fn(...args), wait); };
}


async function loadAll() {
  try {
    // Fetch in parallel
    await Promise.all([
      loadAlerts(),
      loadRules(),
      loadNotifications(),
      loadAudit()
    ]);
  } catch (err) {
    console.error('loadAll error', err);
  }
}


document.addEventListener('DOMContentLoaded', () => {
  wireUp();
  loadAll();
  setInterval(loadAll, REFRESH_INTERVAL_MS);
});
