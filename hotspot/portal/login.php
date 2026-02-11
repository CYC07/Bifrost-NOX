<?php
session_start();
$db = new SQLite3('/tmp/portal_users.db');

if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: /portal/login.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    $password = $_POST['password'];
    
    if (isset($_POST['register'])) {
        $hashed = password_hash($password, PASSWORD_BCRYPT);
        $stmt = $db->prepare('INSERT INTO users (email, password) VALUES (:email, :password)');
        $stmt->bindValue(':email', $email, SQLITE3_TEXT);
        $stmt->bindValue(':password', $hashed, SQLITE3_TEXT);
        
        if ($stmt->execute()) {
            $_SESSION['email'] = $email;
            header('Location: /portal/download_cert.php');
            exit;
        } else {
            $error = "Email already registered!";
        }
    } else {
        $stmt = $db->prepare('SELECT password FROM users WHERE email = :email');
        $stmt->bindValue(':email', $email, SQLITE3_TEXT);
        $result = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
        
        if ($result && password_verify($password, $result['password'])) {
            $_SESSION['email'] = $email;
            
            $update = $db->prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE email = :email');
            $update->bindValue(':email', $email, SQLITE3_TEXT);
            $update->execute();
            
            header('Location: /portal/download_cert.php');
            exit;
        } else {
            $error = "Invalid credentials!";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FYP AI Firewall - Portal</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            padding: 48px 40px;
            border-radius: 24px;
            box-shadow: 0 25px 60px rgba(0, 0, 0, 0.5);
            max-width: 420px;
            width: 90%;
        }
        .logo { text-align: center; font-size: 56px; margin-bottom: 8px; }
        h2 {
            text-align: center;
            color: #e0e0ff;
            margin-bottom: 8px;
            font-size: 24px;
            font-weight: 700;
        }
        .subtitle {
            text-align: center;
            color: rgba(255, 255, 255, 0.5);
            font-size: 14px;
            margin-bottom: 32px;
        }
        input {
            width: 100%;
            padding: 14px 18px;
            margin: 8px 0;
            border: 1px solid rgba(255, 255, 255, 0.15);
            border-radius: 12px;
            font-size: 15px;
            background: rgba(255, 255, 255, 0.08);
            color: #fff;
            transition: all 0.3s ease;
        }
        input::placeholder { color: rgba(255, 255, 255, 0.35); }
        input:focus {
            border-color: #667eea;
            outline: none;
            background: rgba(255, 255, 255, 0.12);
            box-shadow: 0 0 20px rgba(102, 126, 234, 0.2);
        }
        .btn-group { margin-top: 20px; display: flex; flex-direction: column; gap: 10px; }
        button {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            border: none;
            border-radius: 12px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            transition: all 0.3s ease;
            letter-spacing: 0.5px;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(102, 126, 234, 0.4);
        }
        button.register {
            background: transparent;
            border: 1px solid rgba(255, 255, 255, 0.2);
            color: rgba(255, 255, 255, 0.7);
        }
        button.register:hover {
            border-color: #667eea;
            color: #fff;
            box-shadow: 0 8px 25px rgba(102, 126, 234, 0.2);
        }
        .error {
            color: #ff6b6b;
            background: rgba(255, 107, 107, 0.1);
            border: 1px solid rgba(255, 107, 107, 0.2);
            padding: 12px 16px;
            border-radius: 10px;
            margin: 12px 0;
            font-size: 14px;
            text-align: center;
        }
        .footer {
            text-align: center;
            margin-top: 24px;
            color: rgba(255, 255, 255, 0.3);
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">🛡️</div>
        <h2>AI Firewall Portal</h2>
        <p class="subtitle">Register or login to access the network</p>
        <?php if (isset($error)) echo "<div class='error'>$error</div>"; ?>
        
        <form method="POST">
            <input type="email" name="email" placeholder="Email Address" required>
            <input type="password" name="password" placeholder="Password" minlength="4" required>
            <div class="btn-group">
                <button type="submit">Login</button>
                <button type="submit" name="register" value="1" class="register">Create Account</button>
            </div>
        </form>
        <div class="footer">FYP AI Firewall &copy; 2024</div>
    </div>
</body>
</html>
