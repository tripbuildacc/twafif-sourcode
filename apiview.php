<?php
$url = $_GET['url'] ?? '';
    if (!$url) send_text('Missing ?url parameter', 400);
    
$MAX_BYTES        = 256 * 1024;  
$TIMEOUT          = 12;        
$MAX_REDIRECTS    = 5;
$ALLOWED_SCHEMES  = ['http','https'];
$TEXT_EXTS        = ['html','htm','css','js','json','xml','txt','md','php','svg'];

// ---------- HELPERS ----------
function send_text($msg, $code=200) {
    http_response_code($code);
    header('Content-Type: text/plain; charset=utf-8');
    echo $msg;
    exit;
}

function is_private_ip($ip) {
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $long = ip2long($ip);
        $ranges = [
            ['10.0.0.0','10.255.255.255'],
            ['172.16.0.0','172.31.255.255'],
            ['192.168.0.0','192.168.255.255'],
            ['127.0.0.0','127.255.255.255'],
            ['169.254.0.0','169.254.255.255'],
        ];
        foreach ($ranges as $r) if ($long >= ip2long($r[0]) && $long <= ip2long($r[1])) return true;
    } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        if ($ip === '::1') return true;
        if (preg_match('/^fc|^fd/i', $ip)) return true;
    }
    return false;
}

// ---------- MAIN ----------
$url = isset($_GET['url']) ? trim($_GET['url']) : '';
if (!$url) send_text('Missing ?url parameter', 400);
if (!filter_var($url, FILTER_VALIDATE_URL)) send_text('Invalid URL', 400);

$parts = @parse_url($url);
if (!$parts || empty($parts['scheme']) || empty($parts['host'])) send_text('Invalid URL', 400);
if (!in_array(strtolower($parts['scheme']), $ALLOWED_SCHEMES)) send_text('Only http/https allowed', 400);

// quick DNS resolve (A/AAAA)
$host = $parts['host'];
$ips = [];
$dnsA = @dns_get_record($host, DNS_A);
if ($dnsA !== false) foreach ($dnsA as $r) if (!empty($r['ip'])) $ips[] = $r['ip'];
$dnsAAAA = @dns_get_record($host, DNS_AAAA);
if ($dnsAAAA !== false) foreach ($dnsAAAA as $r) if (!empty($r['ipv6'])) $ips[] = $r['ipv6'];
if (empty($ips)) {
    $g = @gethostbyname($host);
    if ($g && $g !== $host) $ips[] = $g;
}
if (empty($ips)) send_text('Cannot resolve host', 400);
foreach ($ips as $ip) {
    if (is_private_ip($ip)) send_text('Blocked private IP (SSRF protection)', 403);
}

// Browser-like headers
$headers = [
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language: en-US,en;q=0.9",
    "Cache-Control: no-cache",
    "Pragma: no-cache",
    "Upgrade-Insecure-Requests: 1",
    "Accept-Encoding: gzip, deflate, br"
];

// HEAD request to inspect content-type/length/status
$ch = curl_init($url);
curl_setopt_array($ch, [
    CURLOPT_NOBODY => true,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HEADER => true,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_MAXREDIRS => $MAX_REDIRECTS,
    CURLOPT_TIMEOUT => $TIMEOUT,
    CURLOPT_HTTPHEADER => $headers,
    CURLOPT_ENCODING => "",
    CURLOPT_USERAGENT => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0 Safari/537.36",
]);
$head = curl_exec($ch);
if ($head === false) { $err = curl_error($ch); curl_close($ch); send_text('HEAD failed: '.$err, 502); }
$info = curl_getinfo($ch);
curl_close($ch);

$http_code = $info['http_code'] ?? 0;
$content_type = $info['content_type'] ?? null;
$content_length = $info['download_content_length'] ?? -1;

if ($http_code < 200 || $http_code >= 400) {
    send_text("Remote returned HTTP $http_code", 502);
}
if ($content_length !== -1 && $content_length > $MAX_BYTES*8) {
    send_text("Remote resource too large ($content_length bytes)", 413);
}

// get extension hint from path or content-type
$path_ext = strtolower(pathinfo($parts['path'] ?? '', PATHINFO_EXTENSION));
$text_like = false;
if ($content_type) {
    $lower_ct = strtolower($content_type);
    if (stripos($lower_ct, 'text/') === 0) $text_like = true;
    $app_prefixes = ['application/json','application/xml','application/javascript','application/xhtml+xml','application/rss+xml','application/atom+xml'];
    foreach ($app_prefixes as $p) if (stripos($lower_ct, $p) === 0) { $text_like = true; break; }
}
if (in_array($path_ext, $TEXT_EXTS)) $text_like = true;

// Now actual GET (with browser-like headers)
$ch = curl_init($url);
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_MAXREDIRS => $MAX_REDIRECTS,
    CURLOPT_TIMEOUT => $TIMEOUT,
    CURLOPT_HTTPHEADER => $headers,
    CURLOPT_ENCODING => "",
    CURLOPT_USERAGENT => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0 Safari/537.36",
]);
$data = curl_exec($ch);
$err = curl_error($ch);
$info = curl_getinfo($ch);
curl_close($ch);

if ($data === false || $err) send_text('Failed fetch: '.$err, 502);

// basic binary check
$is_binary = (strpos($data, "\0") !== false);

// truncate for safety
$truncated = false;
if (strlen($data) > $MAX_BYTES) {
    $data = substr($data, 0, $MAX_BYTES);
    $truncated = true;
}

// decide output
$final_ct = $info['content_type'] ?? $content_type ?? 'application/octet-stream';
if ($text_like && !$is_binary) {
    header('Content-Type: text/plain; charset=utf-8');
    echo $data;
    if ($truncated) echo "\n\n--- [TRUNCATED: preview max {$MAX_BYTES} bytes] ---";
    exit;
} else {
    header('Content-Type: '.($final_ct ?: 'application/octet-stream'));
    header('Content-Length: '.strlen($data));
    echo $data;
    exit;
}
?>