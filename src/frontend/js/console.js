// ==================== CONSOLE ====================
function insertCode(code) {
  document.getElementById('console-input').value = code;
  document.getElementById('console-input').focus();
}

document.getElementById('console-input').addEventListener('keydown', e => {
  if (e.ctrlKey && e.key === 'Enter') runCode();
});

function runCode() {
  const code = document.getElementById('console-input').value.trim();
  if (!code) return;

  const outCard = document.getElementById('output-card');
  const outEl = document.getElementById('console-output');
  outCard.style.display = 'block';
  outEl.innerHTML = '<span class="spinner"></span>Running...';

  const fd = new FormData();
  fd.append('action', 'eval');
  fd.append('code', code);
  fd.append('timeout', '30');

  fetchJSON(fd)
    .then(data => {
      const out = data.output || '(no output)';
      let display = '';
      if (data.error) {
        display += '<div style="color:var(--red);margin-bottom:8px;font-weight:600">' + escHtml(data.error) + '</div>';
      }
      display += '<pre style="margin:0;white-space:pre-wrap">' + escHtml(out) + '</pre>';
      outEl.innerHTML = display;
      dbPut('history', { cmd: code, out, error: data.error || null, ts: new Date().toISOString() });
    })
    .catch(err => { outEl.innerHTML = '<div style="color:var(--red)">Request error: ' + escHtml(String(err)) + '</div>'; });
}

function copyOutput() {
  const text = document.getElementById('console-output').textContent;
  clipCopy(text).then(() => alert('Copied!'));
}

function downloadOutput() {
  const text = document.getElementById('console-output').textContent;
  const blob = new Blob([text], {type: 'text/plain'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'output_' + Date.now() + '.txt';
  a.click();
}
