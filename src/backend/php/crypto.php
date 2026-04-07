// Crypto middleware — decrypts incoming requests and encrypts responses when encryption is active.
// Uses AES-256-CBC with random IV. Key = hex2bin($__AUTH_HASH) = SHA256(password) = 32 bytes.
// Sacrificial buffer pattern: template's ob_start is cleaned, then encryption buffer + sacrificial
// buffer are stacked. Handlers' ob_end_clean() destroys the sacrificial buffer; the encryption
// buffer survives and encrypts output on exit/flush.
if (isset($_POST['__enc']) && isset($__AUTH_HASH) && function_exists('openssl_decrypt')) {
$__CRYPTO_KEY = hex2bin($__AUTH_HASH);
$raw = base64_decode($_POST['__enc'], true);
if ($raw === false || strlen($raw) < 17) {
    ob_end_clean();
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Invalid encrypted payload']);
    exit;
}
$iv = substr($raw, 0, 16);
$ciphertext = substr($raw, 16);
$decrypted = openssl_decrypt($ciphertext, 'AES-256-CBC', $__CRYPTO_KEY, OPENSSL_RAW_DATA, $iv);
if ($decrypted === false) {
    ob_end_clean();
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Decryption failed']);
    exit;
}
parse_str($decrypted, $__dec_params);
$_POST = array_merge($_POST, $__dec_params);
unset($_POST['__enc']);

// Clean template's ob_start
while (ob_get_level()) ob_end_clean();

// Encryption output buffer — callback encrypts everything on flush
ob_start(function($buffer) use ($__CRYPTO_KEY) {
    if (strlen($buffer) === 0) return '';
    $iv = random_bytes(16);
    $enc = openssl_encrypt($buffer, 'AES-256-CBC', $__CRYPTO_KEY, OPENSSL_RAW_DATA, $iv);
    return base64_encode($iv . $enc);
});

// Sacrificial buffer — handlers' ob_end_clean() will destroy this one, not the encryption buffer
ob_start();
}
