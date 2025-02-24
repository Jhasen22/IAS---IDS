<?php
include 'db.php';
$stmt = $pdo->query("SELECT * FROM intrusions ORDER BY timestamp DESC");
$logs = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <link rel="stylesheet" href="style.css">
    <title>Intrusion Logs</title>
</head>
<body>
    <h1>Intrusion Logs</h1>
    <pre><?php foreach ($logs as $log) {
        echo htmlspecialchars("{$log['timestamp']} | IP: {$log['ip']} | Details: {$log['details']}\n");
    } ?></pre>
    <a href="index.php">Back</a>
</body>
</html>
