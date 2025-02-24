<?php include 'detect.php'; ?>
<?php if (!isset($_SESSION['user'])) header('Location: login.php'); ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <style>
        body { font-family: Arial, sans-serif; background: #f5f5f5; color: #333; text-align: center; margin: 40px; }
        h1 { color: #555; }
        a { color: #007bff; text-decoration: none; }
    </style>
</head>
<body>
    <h1>Intrusion Detection System</h1>
    <p>Welcome, <?php echo htmlspecialchars($_SESSION['user']); ?>!</p>
    <p>Monitoring suspicious activities...</p>
    <a href="log.php">View Logs</a> | <a href="logout.php">Logout</a>
</body>
</html>

</html>