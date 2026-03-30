if (isset($_POST['action']) && $_POST['action'] === 'fingerprint') {
ob_end_clean();
set_time_limit(0);
header('Content-Type: application/json');
$host = trim($_POST['host'] ?? '');
$port = (int)($_POST['port'] ?? 0);
$timeout = 4;

if (!$host || !$port) {
echo json_encode(['error' => 'Missing host or port']);
exit;
}

$result = [
'host' => $host,
'port' => $port,
'banner' => '',
'service' => '',
'version' => '',
'info' => [],
'tls' => null,
];

// --- Probe definitions ---
// Ports where the server sends a banner on connect (passive)
$passive = [21,22,23,25,110,143,587,3306,5672,11211];
// Ports needing an active probe
$probes = [
'http' => "HEAD / HTTP/1.0\r\nHost: {$host}\r\nConnection: close\r\n\r\n",
'redis' => "PING\r\n",
'pgsql' => "\x00\x00\x00\x08\x04\xd2\x16\x2f", // SSLRequest
'mongo' => null, // read-only, MongoDB sends greeting since 3.6+
'memcache'=> "stats\r\n",
];

$portProbeMap = [
80 => 'http', 8080 => 'http', 8000 => 'http', 8888 => 'http', 9090 => 'http',
443 => 'https', 8443 => 'https',
6379 => 'redis',
5432 => 'pgsql',
27017 => 'mongo',
11211 => 'memcache',
];

$isHTTPS = in_array($port, [443, 8443]);

// --- TLS certificate extraction (for SSL ports) ---
if ($isHTTPS && function_exists('stream_socket_client')) {
$ctx = stream_context_create(['ssl' => [
'capture_peer_cert' => true,
'verify_peer' => false,
'verify_peer_name' => false,
'allow_self_signed' => true,
]]);
$fp = @stream_socket_client("ssl://{$host}:{$port}", $e, $s, $timeout, STREAM_CLIENT_CONNECT, $ctx);
if ($fp) {
$params = stream_context_get_params($fp);
if (isset($params['options']['ssl']['peer_certificate'])) {
$cert = @openssl_x509_parse($params['options']['ssl']['peer_certificate']);
if ($cert) {
$sans = [];
if (!empty($cert['extensions']['subjectAltName'])) {
preg_match_all('/DNS:([^,\s]+)/', $cert['extensions']['subjectAltName'], $m);
$sans = $m[1] ?? [];
}
$result['tls'] = [
'subject_cn' => $cert['subject']['CN'] ?? '',
'issuer_cn' => $cert['issuer']['CN'] ?? '',
'issuer_org' => $cert['issuer']['O'] ?? '',
'valid_from' => date('Y-m-d', $cert['validFrom_time_t'] ?? 0),
'valid_to' => date('Y-m-d', $cert['validTo_time_t'] ?? 0),
'self_signed' => ($cert['subject'] == $cert['issuer']),
'sans' => $sans,
];
}
}
// Also do HTTP probe over the TLS connection
@fwrite($fp, $probes['http']);
stream_set_timeout($fp, $timeout);
$raw = '';
while (!feof($fp) && strlen($raw) < 8192) $raw .=@fread($fp, 4096);
    fclose($fp);
    if ($raw) $result['banner']=substr($raw, 0, 2048);
    }
    }

    // --- Banner grab via fsockopen (preferred — widely available) ---
    if (!$isHTTPS) {
    $fp=@fsockopen($host, $port, $errno, $errstr, $timeout);
    if ($fp) {
    stream_set_timeout($fp, $timeout);

    $probeType=$portProbeMap[$port] ?? null;

    if (in_array($port, $passive) || $probeType==='mongo' ) {
    // Passive: read banner the server sends
    $result['banner']=@fread($fp, 4096);
    } elseif ($probeType && isset($probes[$probeType])) {
    @fwrite($fp, $probes[$probeType]);
    $raw='' ;
    while (!feof($fp) && strlen($raw) < 8192) $raw .=@fread($fp, 4096);
    $result['banner']=$raw;
    } else {
    // Unknown port: try passive first (1.5s), then HTTP probe
    stream_set_timeout($fp, 2);
    $banner=@fread($fp, 4096);
    if ($banner && strlen(trim($banner))> 0) {
    $result['banner'] = $banner;
    } else {
    @fwrite($fp, $probes['http']);
    stream_set_timeout($fp, $timeout);
    $raw = '';
    while (!feof($fp) && strlen($raw) < 8192) $raw .=@fread($fp, 4096);
        $result['banner']=$raw;
        }
        }
        fclose($fp);
        } else {
        $result['banner']='' ;
        $result['info'][]="Connection failed: $errstr" ;
        }
        }

        // Trim binary garbage, keep printable + common control chars
        $result['banner']=substr($result['banner'], 0, 2048);

        // --- Parse banner into service/version ---
        $b=$result['banner'];

        // SSH
        if (preg_match('/^SSH-[\d.]+-(.+)/m', $b, $m)) {
        $result['service']='SSH' ;
        $result['version']=trim($m[1]);
        // OS hints from SSH banner
        if (preg_match('/Ubuntu/i', $m[1])) $result['info'][]='OS: Ubuntu' ;
        elseif (preg_match('/Debian/i', $m[1])) $result['info'][]='OS: Debian' ;
        elseif (preg_match('/FreeBSD/i', $m[1])) $result['info'][]='OS: FreeBSD' ;
        elseif (preg_match('/RHEL|RedHat/i', $m[1])) $result['info'][]='OS: RHEL' ;
        }
        // FTP
        elseif (preg_match('/^220[- ](.+)/m', $b, $m) && $port==21) {
        $result['service']='FTP' ;
        $result['version']=trim($m[1]);
        if (preg_match('/(vsFTPd|ProFTPD|FileZilla|Pure-FTPd|Microsoft FTP|wu-ftpd)\s*([\d.]*)/i', $m[1], $v)) {
        $result['version']=trim($v[1] . ' ' . $v[2]);
        }
        }
        // SMTP
        elseif (preg_match('/^220[- ](.+)/m', $b, $m) && in_array($port, [25, 465, 587])) {
        $result['service']='SMTP' ;
        $result['version']=trim($m[1]);
        if (preg_match('/(Postfix|Exim|Sendmail|Exchange|hMailServer|Haraka|MailEnable)/i', $m[1], $v))
        $result['version']=trim($v[1]);
        }
        // POP3
        elseif (preg_match('/^\+OK\s*(.*)/m', $b, $m) && $port==110) {
        $result['service']='POP3' ;
        $result['version']=trim($m[1]);
        }
        // IMAP
        elseif (preg_match('/^\* OK\s*(.*)/m', $b, $m) && $port==143) {
        $result['service']='IMAP' ;
        $result['version']=trim($m[1]);
        }
        // MySQL / MariaDB (binary greeting — version at offset 5, null-terminated)
        elseif ($port==3306 && strlen($b)> 5) {
        $result['service'] = 'MySQL';
        $verEnd = strpos($b, "\x00", 5);
        if ($verEnd !== false) {
        $ver = substr($b, 5, $verEnd - 5);
        if (preg_match('/[\d.]+/', $ver, $vm)) {
        $result['version'] = $vm[0];
        if (stripos($ver, 'MariaDB') !== false) $result['service'] = 'MariaDB';
        }
        }
        }
        // Redis
        elseif (preg_match('/^\+PONG/m', $b)) {
        $result['service'] = 'Redis';
        if (preg_match('/redis_version:([\d.]+)/m', $b, $v)) $result['version'] = $v[1];
        }
        // PostgreSQL SSLRequest response
        elseif ($port == 5432 && strlen($b) >= 1) {
        $result['service'] = 'PostgreSQL';
        $result['version'] = ($b[0] === 'S') ? 'SSL supported' : 'No SSL';
        }
        // MongoDB
        elseif ($port == 27017 && strlen($b) > 0) {
        $result['service'] = 'MongoDB';
        if (preg_match('/version["\s:]+([0-9.]+)/i', $b, $v)) $result['version'] = $v[1];
        }
        // Memcached
        elseif (preg_match('/STAT version\s+([\d.]+)/m', $b, $m)) {
        $result['service'] = 'Memcached';
        $result['version'] = $m[1];
        }
        // Elasticsearch (JSON with version)
        elseif (preg_match('/"cluster_name"\s*:\s*"([^"]+)"/', $b, $cn)) {
        $result['service'] = 'Elasticsearch';
        $result['info'][] = 'Cluster: ' . $cn[1];
        if (preg_match('/"number"\s*:\s*"([\d.]+)"/', $b, $v)) $result['version'] = $v[1];
        }
        // Telnet
        elseif ($port == 23) {
        $result['service'] = 'Telnet';
        $printable = preg_replace('/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\xff]/', '', $b);
        $result['version'] = trim(substr($printable, 0, 80));
        }
        // HTTP (catch-all for any port that returned HTTP)
        if (preg_match('/^HTTP\/[\d.]+\s+(\d+)/m', $b, $hm)) {
        if (!$result['service']) $result['service'] = $isHTTPS ? 'HTTPS' : 'HTTP';
        $result['info'][] = 'Status: ' . $hm[1];

        // Server header
        if (preg_match('/^Server:\s*(.+)/mi', $b, $sv)) {
        $result['version'] = trim($sv[1]);
        // OS hints
        if (preg_match('/\(Ubuntu\)/i', $sv[1])) $result['info'][] = 'OS: Ubuntu';
        elseif (preg_match('/\(Debian\)/i', $sv[1])) $result['info'][] = 'OS: Debian';
        elseif (preg_match('/\(CentOS\)/i', $sv[1])) $result['info'][] = 'OS: CentOS';
        elseif (preg_match('/\(Win64\)/i', $sv[1])) $result['info'][] = 'OS: Windows';
        elseif (preg_match('/Microsoft-IIS/i', $sv[1])) $result['info'][] = 'OS: Windows';
        }
        // X-Powered-By
        if (preg_match('/^X-Powered-By:\s*(.+)/mi', $b, $xp))
        $result['info'][] = 'Powered: ' . trim($xp[1]);
        // Cookie-based framework detection
        if (preg_match('/^Set-Cookie:\s*(\S+)/mi', $b, $ck)) {
        $cookie = $ck[1];
        if (stripos($cookie, 'PHPSESSID') !== false) $result['info'][] = 'Framework: PHP';
        elseif (stripos($cookie, 'JSESSIONID') !== false) $result['info'][] = 'Framework: Java';
        elseif (stripos($cookie, 'ASP.NET_SessionId') !== false) $result['info'][] = 'Framework: ASP.NET';
        elseif (stripos($cookie, 'connect.sid') !== false) $result['info'][] = 'Framework: Node/Express';
        elseif (stripos($cookie, 'rack.session') !== false) $result['info'][] = 'Framework: Ruby';
        elseif (stripos($cookie, 'laravel_session') !== false) $result['info'][] = 'Framework: Laravel';
        elseif (stripos($cookie, 'csrftoken') !== false) $result['info'][] = 'Framework: Django';
        elseif (stripos($cookie, '_rails') !== false) $result['info'][] = 'Framework: Rails';
        }
        // X-Generator
        if (preg_match('/^X-Generator:\s*(.+)/mi', $b, $xg))
        $result['info'][] = 'Generator: ' . trim($xg[1]);
        // X-AspNet-Version
        if (preg_match('/^X-AspNet-Version:\s*(.+)/mi', $b, $xa))
        $result['info'][] = '.NET: ' . trim($xa[1]);
        }

        // Clean banner for display — keep only printable ASCII + newlines
        $result['banner'] = preg_replace('/[^\x20-\x7E\r\n\t]/', '.', $result['banner']);
        $result['banner'] = substr(trim($result['banner']), 0, 1024);

        echo json_encode($result);
        exit;
        }
