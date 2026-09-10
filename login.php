<?php
session_set_cookie_params([
  'lifetime' => 0,
  'path' => '/',
  'domain' => '',
  'secure' => true,
  'httponly' => true,
  'samesite' => 'Strict'
]);
session_start();

//$mysqli = new mysqli("localhost", "root", "", "bgmi");

include 'db.php';

if ($mysqli->connect_error) {
    die("Connection failed: " . $mysqli->connect_error);
}

$email = filter_var(trim($_POST['email']), FILTER_VALIDATE_EMAIL);
$password = trim($_POST['password']);
$ip = $_SERVER['REMOTE_ADDR'];

if (!$email || empty($password)) {
    echo "❌ Invalid input.";
    $mysqli->close();
    exit;
}

// 🔹 Clean up old attempts
$mysqli->query("DELETE FROM login_attempts WHERE attempt_time < NOW() - INTERVAL 10 MINUTE");

// 🔹 Count recent attempts
$stmt = $mysqli->prepare("SELECT COUNT(*) FROM login_attempts WHERE ip_address = ?");
$stmt->bind_param("s", $ip);
$stmt->execute();
$stmt->bind_result($attempts);
$stmt->fetch();
$stmt->close();

if ($attempts >= 5) {
    echo "❌ Too many failed attempts. Try again after 10 minutes.";
    $mysqli->close();
    exit;
}

// 🔹 Check if user exists
$stmt = $mysqli->prepare("SELECT id, username, password FROM users WHERE email = ?");
$stmt->bind_param("s", $email);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 1) {
    $user = $result->fetch_assoc();
    if (password_verify($password, $user['password'])) {
        // 🔹 Success → clear attempts
        $stmt->close(); // close SELECT stmt before new prepare

        $stmt = $mysqli->prepare("DELETE FROM login_attempts WHERE ip_address = ?");
        $stmt->bind_param("s", $ip);
        $stmt->execute();
        $stmt->close();

        echo "success:" . htmlspecialchars($user['username']);
    } else {
        // 🔹 Wrong password → insert attempt
        $stmt->close();

        $stmt = $mysqli->prepare("INSERT INTO login_attempts (ip_address, attempt_time) VALUES (?, NOW())");
        $stmt->bind_param("s", $ip);
        $stmt->execute();
        $stmt->close();

        echo "❌ Wrong password";
    }
} else {
    // 🔹 Email not found → insert attempt
    $stmt->close();

    $stmt = $mysqli->prepare("INSERT INTO login_attempts (ip_address, attempt_time) VALUES (?, NOW())");
    $stmt->bind_param("s", $ip);
    $stmt->execute();
    $stmt->close();

    echo "❌ Email not found";
}

$mysqli->close();
?>
