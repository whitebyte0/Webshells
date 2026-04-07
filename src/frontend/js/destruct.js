function selfDestruct() {
  if (!confirm('SELF-DESTRUCT: This will permanently delete the shell file from the server and clear all local data. This cannot be undone.\n\nProceed?')) return;
  if (!confirm('Are you absolutely sure?')) return;

  const fd = new FormData();
  fd.append('action', 'destruct');
  fetchJSON(fd).then(r => {
    if (r.ok) {
      try { indexedDB.deleteDatabase('shelldb'); } catch(e) {}
      try { sessionStorage.clear(); } catch(e) {}
      document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100vh;background:var(--bg,#0d1117);color:var(--green,#3fb950);font-family:monospace;font-size:16px;text-align:center;padding:20px">Shell destroyed successfully.<br>This page is no longer functional.</div>';
    } else {
      alert('Self-destruct failed: ' + (r.error || 'unlink() returned false — check file permissions'));
    }
  }).catch(e => alert('Self-destruct request failed: ' + e.message));
}
