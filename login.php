<?php
session_start();
include 'db.php';

$mode = $_GET['mode'] ?? 'login';
$error = "";
$max_attempts = 5; // Maximum allowed attempts before blocking
$lockout_time = 300; // 5 minutes in seconds

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username']);
    $password = trim($_POST['password']);
    $ip = $_SERVER['REMOTE_ADDR'];

    // Check if user is blocked
    $stmt = $pdo->prepare("SELECT attempts, UNIX_TIMESTAMP(last_attempt) AS last_attempt FROM failed_logins WHERE ip = ?");
    $stmt->execute([$ip]);
    $failed_login = $stmt->fetch();

    $current_time = time();
    $attempts = $failed_login['attempts'] ?? 0;
    $last_attempt_time = $failed_login['last_attempt'] ?? 0;
    
    // If blocked, check if 5 minutes have passed
    if ($attempts >= $max_attempts && ($current_time - $last_attempt_time) < $lockout_time) {
        $remaining_time = $lockout_time - ($current_time - $last_attempt_time);
        $error = "Too many failed attempts. Try again in " . ceil($remaining_time / 60) . " minutes.";
    } else {
        // If lockout time has passed, reset attempts
        if ($attempts >= $max_attempts && ($current_time - $last_attempt_time) >= $lockout_time) {
            $pdo->prepare("DELETE FROM failed_logins WHERE ip = ?")->execute([$ip]);
            $attempts = 0;
        }

        // LOGIN LOGIC
        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch();

        if ($user && password_verify($password, $user['password'])) {
            $_SESSION['user'] = $user['username'];

            // Reset failed login attempts on successful login
            $pdo->prepare("DELETE FROM failed_logins WHERE ip = ?")->execute([$ip]);

            header('Location: index.php');
            exit;
        } else {
            // Calculate remaining attempts
            $attempts_left = $max_attempts - $attempts - 1;
            $error = "Invalid username or password. You have $attempts_left attempts remaining.";

            // Log failed login in `intrusions` table
            $stmt = $pdo->prepare("INSERT INTO intrusions (ip, user_agent, details, timestamp) VALUES (?, ?, ?, NOW())");
            $stmt->execute([$ip, $_SERVER['HTTP_USER_AGENT'], "Failed login attempt for user: $username"]);

            // Update failed login attempts
            if ($failed_login) {
                $pdo->prepare("UPDATE failed_logins SET attempts = attempts + 1, last_attempt = NOW() WHERE ip = ?")
                    ->execute([$ip]);
            } else {
                $pdo->prepare("INSERT INTO failed_logins (ip, username, attempts, last_attempt) VALUES (?, ?, 1, NOW())")
                    ->execute([$ip, $username]);
            }

            // If attempts are exhausted, update message
            if ($attempts_left <= 0) {
                $error = "Too many failed attempts. You are blocked for 5 minutes.";
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= $mode === 'login' ? 'Login' : 'Register' ?> </title>
    <style>
        body {
            background-color:rgb(0, 0, 0);
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            font-family: Arial, sans-serif;
        }
        .container {
            text-align: center;
            width: 350px;
            background: white;
            border: 1px solid #dbdbdb;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.1);
        }
        .logo {
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 20px;
        }
        input {
            width: 100%;
            padding: 10px;
            margin: 8px 0;
            border: 1px solid #dbdbdb;
            border-radius: 5px;
            background: #fafafa;
        }
        .btn {
            width: 100%;
            background:rgb(110, 110, 110);
            color: white;
            border: none;
            padding: 10px;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
        }
        .btn:hover {
            background:rgb(110, 110, 110);
        }
        .error {
            color: red;
            margin-bottom: 10px;
            font-size: 14px;
        }
        .toggle-link {
            margin-top: 15px;
            font-size: 14px;
        }
        .toggle-link a {
            color:rgb(255, 140, 0);
            text-decoration: none;
        }
    </style>
</head>
<body>

    <div class="container">
        <div class="logo">Welcome to Liljhass Realm</div>
        <?php if (!empty($error)) echo "<p class='error'>$error</p>"; ?>
        <form method="post">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit" class="btn"><?= $mode === 'login' ? 'Log in' : 'Sign up' ?></button>
        </form>
        <div class="toggle-link">
            <?= $mode === 'login' ? "Don't have an account? <a href='login.php?mode=register'>Sign up</a>" 
                                 : "Already have an account? <a href='login.php?mode=login'>Log in</a>" ?>
        </div>
    </div>

</body>
</html>
