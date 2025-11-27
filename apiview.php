<?php
$URL = $_GET['url'] ?? '';
if (!$URL) { http_response_code(400); header('Content-Type: text/plain'); echo 'Missing ?url parameter'; exit; }

$MAX_DOWNLOAD_BYTES = 16 * 1024 * 1024;
$TRUNCATE_BYTES = 8 * 1024 * 1024;
$TIMEOUT = 20;
$MAX_REDIRECTS = 25;
$HEADERS_DEFAULT = [
    "Accept: */*",
    "Accept-Language: en-US,en;q=0.9",
    "Cache-Control: no-cache",
    "Pragma: no-cache",
    "Accept-Encoding: gzip, deflate, br"
];

function return_text($msg, $code=200) {
    http_response_code($code);
    header('Content-Type: text/plain; charset=utf-8');
    echo $msg;
    exit;
}
function safe_header($k, $v) {
    if (!headers_sent()) header("$k: $v");
}

if (!filter_var($URL, FILTER_VALIDATE_URL)) return_text('Invalid URL', 400);

$ch = curl_init($URL);
curl_setopt_array($ch, [
    CURLOPT_NOBODY => true,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HEADER => true,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_MAXREDIRS => $MAX_REDIRECTS,
    CURLOPT_TIMEOUT => $TIMEOUT,
    CURLOPT_HTTPHEADER => $HEADERS_DEFAULT,
    CURLOPT_ENCODING => "",
    CURLOPT_USERAGENT => "Fetcher/1.0 (+)",
    CURLOPT_FAILONERROR => false,
]);
$head = @curl_exec($ch);
if ($head === false) { $err = curl_error($ch); curl_close($ch); return_text('HEAD failed: '.$err, 502); }
$info = curl_getinfo($ch);
curl_close($ch);

$remote_cl = $info['download_content_length'] ?? -1;
if ($remote_cl > 0 && $remote_cl > $MAX_DOWNLOAD_BYTES) {
    return_text("Remote resource too large ({$remote_cl} bytes)", 413);
}

$head_ct = $info['content_type'] ?? null;

$ch = curl_init($URL);
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => false,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_MAXREDIRS => $MAX_REDIRECTS,
    CURLOPT_TIMEOUT => $TIMEOUT,
    CURLOPT_HTTPHEADER => $HEADERS_DEFAULT,
    CURLOPT_ENCODING => "",
    CURLOPT_USERAGENT => "Fetcher/1.0 (+)",
    CURLOPT_FAILONERROR => false,
]);

$received = 0;
$parts = [];
$errorDuringWrite = false;
$writeErrMsg = '';

curl_setopt($ch, CURLOPT_WRITEFUNCTION, function($curl, $chunk) use (&$received, &$parts, $MAX_DOWNLOAD_BYTES, &$errorDuringWrite, &$writeErrMsg) {
    $len = strlen($chunk);
    if ($received + $len > $MAX_DOWNLOAD_BYTES) {
        $errorDuringWrite = true;
        $writeErrMsg = "Remote resource exceeded limit";
        return 0;
    }
    $parts[] = $chunk;
    $received += $len;
    return $len;
});

$responseHeaders = [];
curl_setopt($ch, CURLOPT_HEADERFUNCTION, function($curl, $header) use (&$responseHeaders) {
    $len = strlen($header);
    $header = trim($header);
    if ($header === '') return $len;
    $p = strpos($header, ':');
    if ($p !== false) {
        $k = strtolower(trim(substr($header, 0, $p)));
        $v = trim(substr($header, $p + 1));
        $responseHeaders[$k] = $v;
    } else {
        $responseHeaders['__status_line'] = $header;
    }
    return $len;
});

$execOk = curl_exec($ch);
$curlErr = curl_error($ch);
$info = curl_getinfo($ch);
curl_close($ch);

if ($errorDuringWrite) return_text($writeErrMsg, 413);
if ($execOk === false && $curlErr) return_text("Failed fetch: ".$curlErr, 502);

$data = implode('', $parts);
$is_binary = (strpos($data, "\0") !== false);

$final_ct = $responseHeaders['content-type'] ?? $head_ct ?? 'application/octet-stream';

$path = parse_url($URL, PHP_URL_PATH) ?? '';
$ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
$text_exts = ['html','htm','css','js','json','xml','txt','md','php','svg'];
$text_like = false;
if ($final_ct) {
    $lc = strtolower($final_ct);
    if (strpos($lc, 'text/') === 0) $text_like = true;
    foreach (['application/json','application/xml','application/javascript','application/xhtml+xml','application/rss+xml','application/atom+xml'] as $p)
        if (strpos($lc, $p) === 0) $text_like = true;
}
if (in_array($ext, $text_exts)) $text_like = true;
if ($ext === 'php') $text_like = true;

if ($is_binary && strpos($final_ct, 'image/') === 0) {
    $im = @imagecreatefromstring($data);
    if ($im !== false) {
        ob_start();
        $mime = strtolower(explode(';', $final_ct)[0]);
        if ($mime === 'image/jpeg' || $mime === 'image/jpg') imagejpeg($im, null, 75);
        elseif ($mime === 'image/png') imagepng($im, null, 6);
        elseif ($mime === 'image/gif') imagegif($im);
        else { imagejpeg($im, null, 75); $final_ct = 'image/jpeg'; }
        $out = ob_get_clean();
        if ($out) $data = $out;
        imagedestroy($im);
    }
}

$truncated = false;
if (strlen($data) > $TRUNCATE_BYTES) {
    $data = substr($data, 0, $TRUNCATE_BYTES);
    $truncated = true;
}

if ($text_like && !$is_binary) {
    header('Content-Type: text/plain; charset=utf-8');
    echo $data;
    if ($truncated) echo "\n\n--- [TRUNCATED] ---";
    exit;
} else {
    header('Content-Type: '.$final_ct);
    header('Content-Length: '.strlen($data));
    header('Cache-Control: public, max-age=60');
    echo $data;
    exit;
}