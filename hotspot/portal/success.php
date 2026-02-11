<?php
session_start();
if (!isset($_SESSION['email'])) {
    header('Location: /portal/login.php');
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Connected - AI Firewall</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #e0e0ff;
        }
        .container {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            padding: 56px 48px;
            border-radius: 24px;
            box-shadow: 0 25px 60px rgba(0, 0, 0, 0.5);
            max-width: 560px;
            width: 90%;
            text-align: center;
        }
        .icon {
            font-size: 72px;
            margin-bottom: 16px;
            animation: pulse 2s ease-in-out infinite;
        }
        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.1); }
        }
        h2 {
            font-size: 28px;
            margin-bottom: 12px;
            color: #22c55e;
        }
        .message {
            color: rgba(255, 255, 255, 0.6);
            font-size: 16px;
            line-height: 1.7;
            margin-bottom: 32px;
        }
        .features {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 14px;
            margin: 32px 0;
            text-align: left;
        }
        .feature {
            padding: 18px;
            background: rgba(255, 255, 255, 0.04);
            border-radius: 14px;
            border: 1px solid rgba(255, 255, 255, 0.06);
        }
        .feature-icon { font-size: 28px; margin-bottom: 8px; }
        .feature-title {
            font-size: 14px;
            font-weight: 600;
            color: #a5b4fc;
            margin-bottom: 4px;
        }
        .feature-desc {
            font-size: 12px;
            color: rgba(255, 255, 255, 0.4);
            line-height: 1.4;
        }
        .user-info {
            padding: 14px 20px;
            background: rgba(34, 197, 94, 0.1);
            border: 1px solid rgba(34, 197, 94, 0.2);
            border-radius: 12px;
            font-size: 14px;
            color: rgba(255, 255, 255, 0.6);
        }
        .user-info strong { color: #22c55e; }
        .logout {
            display: inline-block;
            margin-top: 24px;
            color: rgba(255, 255, 255, 0.3);
            text-decoration: none;
            font-size: 13px;
            transition: color 0.3s;
        }
        .logout:hover { color: #ff6b6b; }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">✅</div>
        <h2>You're Protected!</h2>
        <p class="message">
            Your device is now connected through the AI Firewall.<br>
            All traffic is being monitored for threats in real-time.
        </p>
        
        <div class="features">
            <div class="feature">
                <div class="feature-icon">🔍</div>
                <div class="feature-title">Content Scanning</div>
                <div class="feature-desc">AI analyzes text & images in real-time</div>
            </div>
            <div class="feature">
                <div class="feature-icon">🚫</div>
                <div class="feature-title">Malware Blocking</div>
                <div class="feature-desc">Executables & suspicious files blocked</div>
            </div>
            <div class="feature">
                <div class="feature-icon">🔐</div>
                <div class="feature-title">HTTPS Inspection</div>
                <div class="feature-desc">Encrypted traffic safely inspected</div>
            </div>
            <div class="feature">
                <div class="feature-icon">🧠</div>
                <div class="feature-title">AI-Powered</div>
                <div class="feature-desc">Deep learning threat detection</div>
            </div>
        </div>
        
        <div class="user-info">
            Connected as: <strong><?php echo htmlspecialchars($_SESSION['email']); ?></strong>
        </div>
        
        <a href="/portal/login.php?logout=1" class="logout">Logout</a>
    </div>
</body>
</html>
