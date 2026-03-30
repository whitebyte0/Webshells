if (isset($_POST['action']) && $_POST['action'] === 'scan') {
ob_end_clean();
set_time_limit(0);
header('Content-Type: application/json');
$cidr = trim($_POST['cidr'] ?? '192.168.2.0/24');
$portStr = trim($_POST['port'] ?? '80');
$timeout = 10;
$open = []; // ['ip:port', ...]

// Parse ports: comma-separated and/or ranges e.g. "22,80,443,8000-8100"
$ports = [];
foreach (explode(',', $portStr) as $part) {
$part = trim($part);
if (strpos($part, '-') !== false) {
list($from, $to) = explode('-', $part, 2);
$from = max(1, (int)$from); $to = min(65535, (int)$to);
for ($p = $from; $p <= $to; $p++) $ports[]=$p;
    } elseif ($part !=='' ) {
    $ports[]=(int)$part;
    }
    }
    $ports=array_values(array_unique(array_filter($ports)));

    // Parse CIDR into list of IPs
    if (strpos($cidr, '/' ) !==false) {
    list($base, $prefix)=explode('/', $cidr);
    $prefix=(int)$prefix;
    $baseInt=ip2long($base);
    if ($baseInt===false) {
    echo json_encode(['error'=> 'Invalid CIDR: ' . $cidr]);
    exit;
    }
    $mask = $prefix === 0 ? 0 : (~0 << (32 - $prefix));
        $network=$baseInt & $mask;
        $count=pow(2, 32 - $prefix);
        $ips=[];
        if ($count===1) {
        // /32 — single host
        $ips[]=long2ip($network);
        } elseif ($count===2) {
        // /31 — point-to-point, both addresses are hosts
        $ips[]=long2ip($network);
        $ips[]=long2ip($network + 1);
        } else {
        for ($i=1; $i < $count - 1; $i++) $ips[]=long2ip($network + $i);
        }
        } else {
        $ips=[];
        for ($i=1; $i <=254; $i++) $ips[]="$cidr.$i" ;
        }
        if (!extension_loaded('sockets')) {
        echo json_encode(['error'=> 'PHP sockets extension not loaded']);
        exit;
        }

        // Non-blocking connect to every ip:port pair simultaneously
        ob_start(); // catch any socket warnings
        $sockets = [];
        foreach ($ips as $ip) {
        foreach ($ports as $port) {
        $sock = @socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        if ($sock === false) continue;
        @socket_set_nonblock($sock);
        @socket_connect($sock, $ip, $port);
        $sockets["$ip:$port"] = $sock;
        }
        }

        // Poll in 500ms increments until timeout expires or all sockets resolved
        $deadline = microtime(true) + $timeout;
        $remaining = $sockets;
        while (!empty($remaining) && microtime(true) < $deadline) {
            usleep(500000); // 0.5s
            foreach ($remaining as $key=> $sock) {
            $r = null; $w = [$sock]; $e = null;
            if (@socket_select($r, $w, $e, 0)) {
            if (@socket_get_option($sock, SOL_SOCKET, SO_ERROR) === 0) {
            $open[] = $key;
            }
            @socket_close($sock);
            unset($remaining[$key]);
            }
            }
            }
            foreach ($remaining as $key => $sock) { @socket_close($sock); }
            ob_end_clean(); // discard any socket warnings

            echo json_encode(['open' => $open, 'total' => count($ips)]);
            exit;
            }
