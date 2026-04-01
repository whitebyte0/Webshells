// ==================== HISTORY ====================
function renderHistory() {
  const body = document.getElementById('history-body');
  body.innerHTML = '<span class="spinner"></span>';
  dbGetAll('history').then(h => {
    if (h.length === 0) {
      body.innerHTML = '<div style="color:var(--muted);font-size:13px">No history yet.</div>';
      return;
    }
    body.innerHTML = h.map(item =>
      '<div class="history-item">' +
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">' +
      '<span class="history-cmd">' + escHtml(item.cmd.substring(0,80)) + (item.cmd.length>80?'...':'') + '</span>' +
      '<div style="display:flex;gap:6px;align-items:center">' +
      '<span style="font-size:11px;color:var(--muted)">' + new Date(item.ts).toLocaleString() + '</span>' +
      '<button class="btn btn-sm btn-secondary" data-ts="' + escHtml(item.ts) + '" onclick="rerun(this.dataset.ts)">Re-run</button>' +
      '<button class="btn btn-sm btn-secondary" data-ts="' + escHtml(item.ts) + '" onclick="copyItem(this.dataset.ts)">Copy</button>' +
      '</div></div>' +
      '<div class="history-out">' + escHtml(item.out.substring(0,500)) + (item.out.length>500?'\n...(truncated)':'') + '</div>' +
      '</div>'
    ).join('');
  });
}

function rerun(ts) {
  dbGetAll('history').then(h => {
    const item = h.find(x => x.ts === ts);
    if (!item) return;
    document.querySelectorAll('.sidebar-nav a').forEach(x => x.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(x => x.classList.remove('active'));
    document.querySelector('[data-tab="console"]').classList.add('active');
    document.getElementById('tab-console').classList.add('active');
    document.getElementById('console-input').value = item.cmd;
  });
}

function copyItem(ts) {
  dbGetAll('history').then(h => {
    const item = h.find(x => x.ts === ts);
    if (item) clipCopy(item.cmd + '\n\n' + item.out);
  });
}

function clearHistory() {
  if (confirm('Clear all command history?')) {
    dbClear('history').then(() => renderHistory());
  }
}

function exportHistory() {
  dbGetAll('history').then(h => {
    const text = h.map(item =>
      '// ' + item.ts + '\n' + item.cmd + '\n\n/* OUTPUT:\n' + item.out + '\n*/\n'
    ).join('\n---\n\n');
    const blob = new Blob([text], {type: 'text/plain'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'shell_history_' + Date.now() + '.txt';
    a.click();
  });
}
