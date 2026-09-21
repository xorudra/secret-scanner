<script>
/* ═══════════════════════════════════════════════
   STATE
═══════════════════════════════════════════════ */
let allFindings    = [];   // raw findings from last scan
let filteredRows   = [];   // after search/filter
let dismissedFPs   = new Set(); // fingerprints dismissed by user
let lastTarget     = 'SecretScanner Web';
let sortKey        = null;
let sortAsc        = true;
let expandedRow    = null;
let scanHistory    = [];   // [{label, icon, iconBg, findings, ts}]

// Pagination
const PAGE_SIZE    = 100;  // rows per page
let currentPage    = 1;

/* ═══════════════════════════════════════════════
   MOBILE SIDEBAR
═══════════════════════════════════════════════ */
function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('open');
}

// Close sidebar when clicking outside on mobile
document.getElementById('main-content').addEventListener('click', () => {
  if (window.innerWidth <= 768) {
    document.getElementById('sidebar').classList.remove('open');
  }
});

/* ═══════════════════════════════════════════════
   NAVIGATION
═══════════════════════════════════════════════ */
function goPage(id) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
  document.getElementById('page-' + id).classList.add('active');
  document.getElementById('nav-' + id).classList.add('active');
  if (id === 'rules') loadRules();
  // Close mobile sidebar on navigation
  if (window.innerWidth <= 768) document.getElementById('sidebar').classList.remove('open');
}

/* ═══════════════════════════════════════════════
   TOAST
═══════════════════════════════════════════════ */
function toast(msg, type='info', duration=4000) {
  const icons = { success:'fa-circle-check', error:'fa-circle-exclamation', warn:'fa-triangle-exclamation', info:'fa-circle-info' };
  const colors = { success:'var(--safe)', error:'var(--crit)', warn:'var(--med)', info:'var(--indigo)' };
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.innerHTML = `<i class="fa-solid ${icons[type]}" style="color:${colors[type]};font-size:1rem;flex-shrink:0"></i><span>${msg}</span>`;
  document.getElementById('toast-container').appendChild(el);
  setTimeout(() => el.remove(), duration);
}

/* ═══════════════════════════════════════════════
   PROGRESS
═══════════════════════════════════════════════ */
function showProgress(id) { document.getElementById(id).classList.add('visible'); }
function hideProgress(id) { document.getElementById(id).classList.remove('visible'); }

function setBtn(id, loading, originalHTML) {
  const btn = document.getElementById(id);
  if (loading) {
    btn._orig = btn.innerHTML;
    btn.innerHTML = '<span class="spinner"></span> Scanning…';
    btn.disabled = true;
  } else {
    btn.innerHTML = btn._orig || originalHTML;
    btn.disabled = false;
  }
}

/* ═══════════════════════════════════════════════
   SCAN — PATH
═══════════════════════════════════════════════ */
async function runPathScan() {
  const path = document.getElementById('path-input').value.trim() || '.';
  lastTarget  = path;
  setBtn('btn-path', true);
  showProgress('prog-path');
  try {
    const res  = await fetch('/scan', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({path}) });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Scan failed');
    commitFindings(data.findings, path, 'fa-folder-open', 'rgba(99,102,241,.2)');
  } catch(e) { toast('Scan error: ' + e.message, 'error'); }
  finally { setBtn('btn-path', false); hideProgress('prog-path'); }
}

/* ═══════════════════════════════════════════════
   SCAN — TEXT
═══════════════════════════════════════════════ */
async function runTextScan() {
  const text = document.getElementById('text-snippet').value;
  if (!text.trim()) { toast('Paste some code first.', 'warn'); return; }
  lastTarget  = 'Inline Snippet';
  setBtn('btn-text', true);
  showProgress('prog-text');
  try {
    const res  = await fetch('/scan/text', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({text}) });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Scan failed');
    commitFindings(data.findings, 'Code Snippet', 'fa-file-code', 'rgba(34,211,238,.15)');
  } catch(e) { toast('Scan error: ' + e.message, 'error'); }
  finally { setBtn('btn-text', false); hideProgress('prog-text'); }
}

/* ═══════════════════════════════════════════════
   SCAN — GIT
═══════════════════════════════════════════════ */
async function runGitScan() {
  const path = document.getElementById('git-path').value.trim() || '.';
  const maxVal = document.getElementById('git-max-commits').value.trim();
  const maxCommits = maxVal ? parseInt(maxVal, 10) : null;
  lastTarget  = 'Git: ' + path;

  const isRemote = /^(https?|git@|ssh:\/\/)/.test(path);
  document.get