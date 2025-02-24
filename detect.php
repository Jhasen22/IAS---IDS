<?php
session_start();
include_once 'db.php';  // Prevents duplicate inclusion

if (!function_exists('log_intrusion')) { // Prevents redeclaration
    function log_intrusion($ip, $user_agent, $details, $pdo) {
        $stmt = $pdo->prepare("INSERT INTO intrusions (ip, user_agent, details, timestamp) VALUES (?, ?, ?, NOW())");
        $stmt->execute([$ip, $user_agent, $details]);
    }
}

$ip = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';
$user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'UNKNOWN';
$request_uri = $_SERVER['REQUEST_URI'] ?? '';

if (preg_match('/(<script>|<|>|union|select|insert|drop|--)/i', $request_uri)) {
    log_intrusion($ip, $user_agent, "Possible SQLi/XSS: $request_uri", $pdo);
    die("Access denied.");
}
?>
