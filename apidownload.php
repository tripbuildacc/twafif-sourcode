<?php
$url = $_GET['url'] ?? '';
    if (!$url) send_text('Missing ?url parameter', 400);

$MAX_BYTES        = 4 * 1024 * 1024; // 4 MB max download
$TIMEOUT          = 15;
$MAX_REDIRECTS    = 5;
$ALLOWED_SCHEMES  = ['http','https'];
$TEXT_CT_MAP = [
    'text/html' => 'html',
    'application/json' => 'json',
    'application/xml' => 'xml',
    'text/xml' => 'xml',
    'text/css' => 'css',
    'application/javascript' => 'js',
];

// ---------- HELPERS ----------
function send_error($msg, $code=400) {
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
function safe_filename($s) {
    $s = preg_replace('#[\/\\\\]+#', '-', $s);
    $s = preg_replace('/[^A-Za-z0-9\-\._]/', '-', $s);
    $s = preg_replace('/-+/', '-', $s);
    return trim($s, '-._');
}

// ---------- MAIN ----------
$client_ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
// rate limit dihapus

$url = isset($_GET['url']) ? trim($_GET['url']) : '';
if (!$url) send_error('Missing ?url', 400);
if (!filter_var($url, FILTER_VALIDATE_URL)) send_error('Invalid URL', 400);

$parts = parse_url($url);
if (!$parts || !isset($parts['host']) || !isset($parts['scheme'])) send_error('Invalid URL', 400);
if (!in_array(strtolower($parts['scheme']), $ALLOWED_SCHEMES)) send_error('Only http/https allowed', 400);

// DNS resolve and SSRF block
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
if (empty($ips)) send_error('Cannot resolve host', 400);
foreach ($ips as $ip) {
    if (is_private_ip($ip)) send_error('Blocked private IP', 403);
}

// HEAD request with browser-like headers
$headers = [
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language: en-US,en;q=0.9",
    "Cache-Control: no-cache",
    "Pragma: no-cache",
    "Upgrade-Insecure-Requests: 1",
    "Sec-Fetch-Site: none",
    "Sec-Fetch-Mode: navigate",
    "Sec-Fetch-User: ?1",
    "Sec-Fetch-Dest: document",
    "Accept-Encoding: gzip, deflate, br"
];

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
if ($head === false) { $err = curl_error($ch); curl_close($ch); send_error('HEAD failed: '.$err, 502); }
$info = curl_getinfo($ch);
curl_close($ch);

$http_code = $info['http_code'] ?? 0;
$content_type = $info['content_type'] ?? null;
$content_length = $info['download_content_length'] ?? -1;

if ($http_code == 403 || $http_code == 401) send_error("Blocked by remote server (HTTP $http_code).", 403);
if ($http_code < 200 || $http_code >= 400) send_error("Remote returned HTTP $http_code", 502);
if ($content_length !== -1 && $content_length > $MAX_BYTES) send_error("Remote resource too large (Content-Length: $content_length)", 413);

// determine filename pattern Raw_<host>---<path>.ext
$path = $parts['path'] ?? '/';
if ($path === '' || substr($path, -1) === '/') $path = rtrim($path, '/') . '/index.html';
$cleanPathForName = ltrim($path, '/');
$ext = strtolower(pathinfo($cleanPathForName, PATHINFO_EXTENSION));
if ($ext === '') {
    // fallback using content-type
    $ctLower = strtolower($content_type ?? '');
    $foundExt = null;
    foreach ($TEXT_CT_MAP as $k => $v) {
        if (stripos($ctLower, $k) === 0) { $foundExt = $v; break; }
    }
    $ext = $foundExt ?: 'txt';
}
$hostSafe = preg_replace('/[^A-Za-z0-9\.\-]/', '', $host);
$pathSafe = str_replace('/', '-', $cleanPathForName);
$pathSafe = preg_replace('/-+/', '-', $pathSafe);
$pathSafe = safe_filename($pathSafe);
$filename = "Raw_{$hostSafe}---{$pathSafe}";
if (substr($filename, -strlen($ext)) !== $ext) $filename .= '.' . $ext;

// GET content with same browser-like headers
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

if ($data === false || $err) send_error('Fetch error: '.$err, 502);

// truncate if way too large
if (strlen($data) > $MAX_BYTES) $data = substr($data, 0, $MAX_BYTES);

// force download
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="' . $filename . '"');
header('Content-Length: ' . strlen($data));
echo $data;
exit;
?>