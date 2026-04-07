if (isset($_POST['action']) && $_POST['action'] === 'destruct') {
ob_end_clean();
header('Content-Type: application/json');
$file = __FILE__;
$ok = @unlink($file);
if (session_status() === PHP_SESSION_ACTIVE) {
    session_destroy();
}
echo json_encode(['ok' => $ok, 'destroyed' => $ok]);
exit;
}
