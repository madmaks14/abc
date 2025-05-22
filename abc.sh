#!/bin/bash
set -e

echo "[+] Updating packages..."
sudo apt update

echo "[+] Installing Apache2, PHP, MariaDB, and required extensions..."
sudo apt install apache2 php libapache2-mod-php php-mysql mariadb-server unzip -y

# Start MariaDB normally
sudo systemctl enable mariadb
sudo systemctl start mariadb

# Create secure MariaDB user and login DB
echo "[+] Creating login_db and admin user..."
HASHED_PASS=$(php -r "echo password_hash('abc123', PASSWORD_DEFAULT);")

sudo mysql <<EOF
CREATE DATABASE IF NOT EXISTS login_db;
CREATE USER IF NOT EXISTS 'webadmin'@'localhost' IDENTIFIED BY 'webpass';
GRANT ALL PRIVILEGES ON login_db.* TO 'webadmin'@'localhost';
FLUSH PRIVILEGES;
USE login_db;
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL
);
DELETE FROM users WHERE username='admin';
INSERT INTO users (username, password) VALUES ('admin', '$HASHED_PASS');
EOF

# Setup web root
echo "[+] Preparing web root..."
sudo mkdir -p /var/www/html/login
sudo chown -R $USER:www-data /var/www/html/login
sudo chmod -R 755 /var/www/html/login

# Redirect / to login page using PHP redirect
echo "[+] Creating index.php redirect to login page..."
echo '<?php header("Location: /login/login.html"); exit(); ?>' | sudo tee /var/www/html/index.php > /dev/null

# Write db_config.php
cat <<'PHP' | sudo tee /var/www/html/login/db_config.php > /dev/null
<?php
$host = '127.0.0.1';
$db = 'login_db';
$user = 'webadmin';
$pass = 'webpass';
try {
    $pdo = new PDO("mysql:host=$host;dbname=$db;charset=utf8", $user, $pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Database connection failed: " . $e->getMessage());
}
?>
PHP

# Write login.html
cat <<'HTML' | sudo tee /var/www/html/login/login.html > /dev/null
<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
    <h2>Login Page</h2>
    <form method="post" action="login.php">
        Username: <input type="text" name="username" required><br><br>
        Password: <input type="password" name="password" required><br><br>
        <input type="submit" value="Login">
    </form>
</body>
</html>
HTML

# Write login.php
cat <<'PHP' | sudo tee /var/www/html/login/login.php > /dev/null
<?php
session_start();
require 'db_config.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];

    $stmt = $pdo->prepare("SELECT password FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user && password_verify($password, $user['password'])) {
        $_SESSION['logged_in'] = true;
        header("Location: dashboard.php");
        exit();
    } else {
        echo "Invalid username or password.";
    }
}
?>
PHP

# Write logout.php
cat <<'PHP' | sudo tee /var/www/html/login/logout.php > /dev/null
<?php
session_start();
session_unset();
session_destroy();
header("Location: login.html");
exit();
?>
PHP

# Write dashboard.php
cat <<'PHP' | sudo tee /var/www/html/login/dashboard.php > /dev/null
<?php
session_start();
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    header("Location: login.html");
    exit();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>IP and Location Viewer</title>
    <link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css" />
    <style>
        body { font-family: Arial, sans-serif; text-align: center; margin: 20px; }
        #map { height: 400px; width: 80%; margin: auto; margin-top: 20px; }
        .info { margin-top: 10px; }
    </style>
</head>
<body>
    <h1>IP and Location Information</h1>
    <div class="info">
        <p><strong>Local IP:</strong> <span id="local-ip">Detecting...</span></p>
        <p><strong>Public IP:</strong> <span id="public-ip">Detecting...</span></p>
        <p><strong>Location:</strong> <span id="location">Detecting...</span></p>
    </div>
    <div id="map"></div>
    <p><a href="logout.php">Logout</a></p>

    <script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>
    <script>
        function getLocalIP(callback) {
            let pc = new RTCPeerConnection({iceServers: []});
            pc.createDataChannel('');
            pc.createOffer().then(offer => pc.setLocalDescription(offer));
            pc.onicecandidate = (ice) => {
                if (!ice || !ice.candidate || !ice.candidate.candidate) return;
                const ipRegex = /([0-9]{1,3}(\\.[0-9]{1,3}){3})/;
                const ipMatch = ice.candidate.candidate.match(ipRegex);
                if (ipMatch) {
                    callback(ipMatch[1]);
                }
                pc.close();
            };
        }

        getLocalIP(ip => {
            document.getElementById('local-ip').textContent = ip;
        });

        fetch('https://ipinfo.io/json')
            .then(response => response.json())
            .then(data => {
                const publicIP = data.ip;
                const loc = data.loc.split(',');
                const city = data.city;
                const region = data.region;
                const country = data.country;

                document.getElementById('public-ip').textContent = publicIP;
                document.getElementById('location').textContent = `${city}, ${region}, ${country}`;

                const lat = parseFloat(loc[0]);
                const lon = parseFloat(loc[1]);

                const map = L.map('map').setView([lat, lon], 10);
                L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                    attribution: 'Map data © <a href="https://openstreetmap.org">OpenStreetMap</a> contributors'
                }).addTo(map);

                L.marker([lat, lon]).addTo(map)
                    .bindPopup(`You are near ${city}, ${country}`)
                    .openPopup();
            })
            .catch(error => {
                console.error('Error fetching public IP/location:', error);
            });
    </script>
</body>
</html>
PHP

echo "[+] Restarting Apache..."
sudo systemctl restart apache2

echo "[✓] Setup complete! Go to: http://localhost/"

