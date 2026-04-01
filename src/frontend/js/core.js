// Base URL — always post to script path without query params
const BASE_URL = location.pathname;

// Safe fetch — returns parsed JSON or throws with raw body visible in message
function fetchJSON(fd) {
  return fetch(BASE_URL, { method: 'POST', body: fd })
    .then(r => r.text())
    .then(text => {
      try { return JSON.parse(text); }
      catch(e) { throw new Error('PHP returned non-JSON:\n' + text.substring(0, 500)); }
    });
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function clipCopy(text) {
  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(text);
  }
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.left = '-9999px';
  document.body.appendChild(ta);
  ta.select();
  document.execCommand('copy');
  document.body.removeChild(ta);
  return Promise.resolve();
}

// ==================== TAB NAVIGATION ====================
document.querySelectorAll('.sidebar-nav a').forEach(a => {
  a.addEventListener('click', e => {
    e.preventDefault();
    document.querySelectorAll('.sidebar-nav a').forEach(x => x.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(x => x.classList.remove('active'));
    a.classList.add('active');
    document.getElementById('tab-' + a.dataset.tab).classList.add('active');
    if (a.dataset.tab === 'history' && typeof renderHistory === 'function') renderHistory();
    if (a.dataset.tab === 'files' && typeof browseDir === 'function') browseDir(document.getElementById('files-path-input').value);
    if (a.dataset.tab === 'diag' && typeof loadDiag === 'function') loadDiag();
  });
});
