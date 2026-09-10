<?php
//$mysqli = new mysqli("localhost", "root", "", "bgmi");
include 'db.php';

if ($mysqli->connect_error) {
    die("Connection failed: " . $mysqli->connect_error);
}

$email = filter_var(trim($_POST['email']), FILTER_VALIDATE_EMAIL);
if (!$email) {
    die("❌ Invalid email");
}

// Check if user exists
$stmt = $mysqli->prepare("SELECT id FROM users WHERE email = ?");
$stmt->bind_param("s", $email);
$stmt->execute();
$stmt->store_result();

if ($stmt->num_rows === 0) {
    die("❌ Email not found");
}
$stmt->close();

// Generate token
$token = bin2hex(random_bytes(32));
$expires = date("Y-m-d H:i:s", strtotime("+1 hour"));

// Remove old token for this email
$stmt = $mysqli->prepare("DELETE FROM password_resets WHERE email = ?");
$stmt->bind_param("s", $email);
$stmt->execute();
$stmt->close();

// Insert new token
$stmt = $mysqli->prepare("INSERT INTO password_resets (email, token, expires_at) VALUES (?, ?, ?)");
$stmt->bind_param("sss", $email, $token, $expires);
$stmt->execute();
$stmt->close();

// Send email (or show link for testing)
$reset_link = "http://localhost/bgmi-site/reset-password.php?token=$token";

$subject = "Password Reset Request";
$message = "Click the following link to reset your password:\n$reset_link\nThis link expires in 1 hour.";
$headers = "From: noreply@bgmi-site.local";

if (mail($email, $subject, $message, $headers)) {
    echo "✅ Reset link sent to your email.";
} else {
    echo "✅ For testing: <a href=\"$reset_link\">$reset_link</a>";
}

$mysqli->close();
?>
