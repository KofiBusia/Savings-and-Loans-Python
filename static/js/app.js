/* Shared utilities for Ghana Savings & Loans web portal */
'use strict';

const BASE = '/api/v1';

// ── Auth helpers ────────────────────────────────────────────────────────────
const Auth = {
  getToken:        () => localStorage.getItem('gsl_token'),
  setToken:        (t) => localStorage.setItem('gsl_token', t),
  getRefresh:      () => localStorage.getItem('gsl_refresh'),
  setRefresh:      (t) => localStorage.setItem('gsl_refresh', t),
  clear:           () => { localStorage.removeItem('gsl_token'); localStorage.removeItem('gsl_refresh'); },

  payload() {
    const t = this.getToken();
    if (!t) return null;
    try { return JSON.parse(atob(t.split('.')[1])); } catch { return null; }
  },
  getRoles()   { return this.payload()?.roles || []; },
  hasRole(r)   { return this.getRoles().includes(r); },
  isCustomer() { return this.payload()?.type === 'customer_access'; },
  isStaff()    { return this.payload()?.type === 'access'; },
  isAdmin()    { return this.hasRole('SUPER_ADMIN') || this.hasRole('ADMIN'); },
  isExpired()  {
    const p = this.payload();
    return !p || p.exp < Math.floor(Date.now() / 1000);
  },
};

// ── API client ───────────────────────────────────────────────────────────────
async function api(method, path, body = null, opts = {}) {
  const token = Auth.getToken();
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const fetchOpts = { method, headers, ...opts };
  if (body !== null) fetchOpts.body = JSON.stringify(body);

  const res = await fetch(BASE + path, fetchOpts);

  if (res.status === 401) { Auth.clear(); location.href = '/'; throw new Error('Session expired'); }

  if (!res.ok) {
    let msg = res.statusText;
    try {
      const j = await res.json();
      msg = typeof j.detail === 'string' ? j.detail
          : Array.isArray(j.detail) ? j.detail.map(e => e.msg || e).join('; ')
          : JSON.stringify(j.detail);
    } catch {}
    throw new Error(msg);
  }
  if (res.status === 204) return null;
  return res.json();
}

// ── Format helpers ──────────────────────────────────────────────────────────
function fmt(n)  { return 'GHS ' + parseFloat(n || 0).toLocaleString('en-GH', { minimumFractionDigits: 2 }); }
function fmtD(d) { if (!d) return '—'; return new Date(d).toLocaleDateString('en-GB', { day:'2-digit', month:'short', year:'numeric' }); }
function fmtDT(d){ if (!d) return '—'; return new Date(d).toLocaleString('en-GB',  { day:'2-digit', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' }); }

const STATUS_COLORS = {
  ACTIVE:'success', APPLICATION:'warning', APPROVED:'info', DISBURSED:'primary',
  OVERDUE:'danger', SETTLED:'secondary', REJECTED:'danger', PENDING_ACTIVATION:'warning',
  DORMANT:'secondary', FROZEN:'danger', PENDING_GHANA_CARD:'warning', OPEN:'danger',
  CREDIT_CHECK:'warning', UNDER_REVIEW:'warning', FILED_CTR:'info', FILED_STR:'info',
  DISMISSED:'secondary', CANCELLED:'secondary', WRITTEN_OFF:'dark',
};
function badge(s, lbl) {
  const c = STATUS_COLORS[s] || 'secondary';
  return `<span class="badge bg-${c}">${(lbl||s).replace(/_/g,' ')}</span>`;
}

// ── Toast notifications ──────────────────────────────────────────────────────
function toast(msg, type = 'success') {
  let c = document.getElementById('toastContainer');
  if (!c) { c = document.createElement('div'); c.id = 'toastContainer';
    c.className = 'toast-container position-fixed bottom-0 end-0 p-3'; c.style.zIndex = 1200;
    document.body.appendChild(c); }
  const id = 'toast_' + Date.now();
  c.insertAdjacentHTML('beforeend', `
    <div id="${id}" class="toast align-items-center text-bg-${type} border-0" role="alert">
      <div class="d-flex">
        <div class="toast-body">${msg}</div>
        <button class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
      </div>
    </div>`);
  new bootstrap.Toast(document.getElementById(id), { delay: 4500 }).show();
}

// ── Spinner overlay ──────────────────────────────────────────────────────────
function showSpinner() {
  if (document.getElementById('_spin')) return;
  document.body.insertAdjacentHTML('beforeend',
    `<div id="_spin" class="spinner-overlay"><div class="spinner-border text-light"></div></div>`);
}
function hideSpinner() { document.getElementById('_spin')?.remove(); }

// ── Route guard ─────────────────────────────────────────────────────────────
function requireAuth(expected) {
  if (!Auth.getToken() || Auth.isExpired()) { Auth.clear(); location.href = '/'; return false; }
  if (expected === 'customer' && !Auth.isCustomer()) {
    location.href = Auth.isStaff() ? '/staff' : '/'; return false;
  }
  if (expected === 'staff' && Auth.isCustomer()) {
    location.href = '/customer'; return false;
  }
  return true;
}

// ── Logout ───────────────────────────────────────────────────────────────────
async function logout() {
  const rt = Auth.getRefresh();
  if (rt) { try { await api('POST', '/auth/logout', { refresh_token: rt }); } catch {} }
  Auth.clear();
  location.href = '/';
}

// ── Hash-based section router ────────────────────────────────────────────────
function initNav(sections, defaultSection, loader) {
  function go() {
    const hash = (location.hash || '#' + defaultSection).slice(1) || defaultSection;
    sections.forEach(s => {
      const el = document.getElementById('sec-' + s);
      if (el) el.classList.toggle('d-none', s !== hash);
    });
    document.querySelectorAll('[data-section]').forEach(a => {
      a.classList.toggle('active', a.dataset.section === hash);
    });
    loader(hash);
  }
  window.addEventListener('hashchange', go);
  go();
}

// ── Simple confirm dialog ────────────────────────────────────────────────────
function confirm2(msg) { return window.confirm(msg); }

// ── Table builder helper ─────────────────────────────────────────────────────
function buildTable(headers, rows) {
  const ths = headers.map(h => `<th>${h}</th>`).join('');
  const trs = rows.length
    ? rows.map(r => `<tr>${r.map(c => `<td>${c ?? '—'}</td>`).join('')}</tr>`).join('')
    : `<tr><td colspan="${headers.length}" class="text-center text-muted py-4">No records found</td></tr>`;
  return `<div class="table-responsive"><table class="table table-hover mb-0">
    <thead><tr>${ths}</tr></thead><tbody>${trs}</tbody></table></div>`;
}
