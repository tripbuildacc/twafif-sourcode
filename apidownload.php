<?php

if (!isset($_GET['url'])) {
    header("Content-Type: text/plain");
    echo "missing ?url=";
    exit;
}

$url = $_GET['url'];

$ch = curl_init($url);
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_MAXREDIRS => 25,
    CURLOPT_SSL_VERIFYPEER => false,
    CURLOPT_SSL_VERIFYHOST => false,
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_TIMEOUT => 60,
    CURLOPT_USERAGENT => "Mozilla/5.0",
]);
$data = curl_exec($ch);
$info = curl_getinfo($ch);
curl_close($ch);

if ($data === false) {
    header("Content-Type: text/plain");
    echo "download failed";
    exit;
}

$hostname = parse_url($url, PHP_URL_HOST);
$path = parse_url($url, PHP_URL_PATH);

if (!$hostname) $hostname = "unknown";
if (!$path || $path === "/") $path = "index.html";

$basename = basename($path);
$filename = $hostname . "--" . $basename;

if (strlen($data) > 16 * 1024 * 1024) {
    $data = substr($data, 0, 8 * 1024 * 1024);
}

$ext = strtolower(pathinfo($basename, PATHINFO_EXTENSION));
if (in_array($ext, ["jpg", "jpeg", "png", "gif", "webp"])) {
    $image = @imagecreatefromstring($data);
    if ($image) {
        ob_start();
        if ($ext === "png") imagepng($image, null, 9);
        else imagejpeg($image, null, 80);
        $data = ob_get_clean();
    }
}

header("Content-Type: application/octet-stream");
header("Content-Disposition: attachment; filename=\"$filename\"");
header("Content-Length: " . strlen($data));

echo $data;