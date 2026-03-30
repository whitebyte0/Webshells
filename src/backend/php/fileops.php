if (isset($_POST['action']) && $_POST['action'] === 'delete') {
ob_end_clean();
header('Content-Type: application/json');
$path = $_POST['path'] ?? '';
if (!$path || !file_exists($path) || is_dir($path)) {
echo json_encode(['error' => 'Invalid path']);
exit;
}
try {
if (!@unlink($path)) throw new Exception('unlink() failed — check permissions');
echo json_encode(['ok' => true]);
} catch (Exception $e) {
echo json_encode(['error' => $e->getMessage()]);
}
exit;
}

if (isset($_POST['action']) && $_POST['action'] === 'upload') {
ob_end_clean();
header('Content-Type: application/json');
$dir = $_POST['dir'] ?? '';
if (!$dir || !is_dir($dir)) {
echo json_encode(['error' => 'Invalid directory']);
exit;
}
if (empty($_FILES['file'])) {
echo json_encode(['error' => 'No file received']);
exit;
}
try {
$name = basename($_FILES['file']['name']);
$dest = rtrim($dir, '/') . '/' . $name;
if (!@move_uploaded_file($_FILES['file']['tmp_name'], $dest)) {
throw new Exception('move_uploaded_file() failed — check permissions');
}
echo json_encode(['ok' => true, 'path' => $dest]);
} catch (Exception $e) {
echo json_encode(['error' => $e->getMessage()]);
}
exit;
}
