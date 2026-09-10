<?php

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

echo "✔ PHP loaded<br>";

session_set_cookie_params([
  'lifetime' => 0,
  'path' => '/',
  'domain' => '', 
  'secure' => true,
  'httponly' => true,
  'samesite' => 'Strict'
]);
session_start();

echo "✔ Session started<br>";

// include DB
include 'db.php';
echo "✔ DB file included<br>";

if ($mysqli->connect_error) {
    die("❌ DB Connection failed: " . $mysqli->connect_error);
}
echo "✔ DB connected<br>";

// fetch form fields
$username = htmlspecialchars(trim($_POST['username']));
$email = filter_var(trim($_POST['email']), FILTER_VALIDATE_EMAIL);
$password = $_POST['password'];
$phone = trim($_POST['phone']);

echo "✔ Input received - username: $username, email: $email, phone: $phone<br>";

// validation
if (!$email) {
    die("❌ Invalid email");
}
if (!preg_match('/^[0-9]{10}$/', $phone)) {
    die("❌ Invalid phone number");
}
if (strlen($password) < 12) {
    die("❌ Password must be at least 12 characters");
}
echo "✔ Validation passed<br>";

// check if email exists
$stmt = $mysqli->prepare("SELECT id FROM users WHERE email = ?");
if (!$stmt) {
    die("❌ Prepare failed (email check): " . $mysqli->error);
}
$stmt->bind_param("s", $email);
$stmt->execute();
$stmt->store_result();
if ($stmt->num_rows > 0) {
    echo "❌ Email already registered";
    $stmt->close();
    $mysqli->close();
    exit;
}
$stmt->close();
echo "✔ Email not registered, continue<br>";

// insert user
$hashedPassword = password_hash($password, PASSWORD_DEFAULT);
$stmt = $mysqli->prepare("INSERT INTO users (username, email, password, phone) VALUES (?, ?, ?, ?)");
if (!$stmt) {
    die("❌ Prepare failed (insert): " . $mysqli->error);
}
$stmt->bind_param("ssss", $username, $email, $hashedPassword, $phone);

if ($stmt->execute()) {
    echo "✅ success:" . htmlspecialchars($username);
} else {
    echo "❌ Registration failed: " . $stmt->error;
}

$stmt->close();
$mysqli->close();
?>
