<?php
session_start();
if (!isset($_SESSION['email'])) {
    header('Location: /portal/login.php');
    exit;
}

$db = new SQLite3('/tmp/portal_users.db');

if (isset($_GET['download'])) {
    $stmt = $db->prepare('UPDATE users SET cert_downloaded = 1 WHERE email = :email');
    $stmt->bindValue(':email', $_SESSION['email'], SQLITE3_TEXT);
    $stmt->execute();
    
    $cert_file = '/var/www/html/certs/AI-Firewall-CA.crt';
    if (file_exists($cert_file)) {
        header('Content-Type: application/x-x509-ca-cert');
        header('Content-Disposition: attachment; filename="AI-Firewall-CA.crt"');
        readfile($cert_file);
        exit;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Install Certificate - AI Firewall</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
            min-height: 100vh;
            padding: 40px 20px;
            color: #e0e0ff;
        }
        .container {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            padding: 48px 40px;
            border-radius: 24px;
            box-shadow: 0 25px 60px rgba(0, 0, 0, 0.5);
            max-width: 680px;
            margin: 0 auto;
        }
        h2 { font-size: 28px; margin-bottom: 8px; }
        .subtitle {
            color: rgba(255, 255, 255, 0.5);
            font-size: 14px;
            margin-bottom: 32px;
        }
        .warning {
            background: rgba(255, 193, 7, 0.1);
            border: 1px solid rgba(255, 193, 7, 0.3);
            padding: 18px 20px;
            border-radius: 14px;
            margin: 24px 0;
            font-size: 14px;
            line-height: 1.6;
        }
        .warning strong { color: #ffc107; }
        h3 {
            font-size: 18px;
            margin: 28px 0 16px;
            color: #a5b4fc;
        }
        .steps {
            list-style: none;
            counter-reset: step;
        }
        .steps li {
            counter-increment: step;
            padding: 14px 18px 14px 56px;
            position: relative;
            margin: 8px 0;
            background: rgba(255, 255, 255, 0.04);
            border-radius: 12px;
            font-size: 15px;
            line-height: 1.5;
        }
        .steps li::before {
            content: counter(step);
            position: absolute;
            left: 18px;
            top: 14px;
            width: 26px;
            height: 26px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 13px;
            font-weight: 700;
        }
        .steps li strong { color: #a5b4fc; }
        .download-btn {
            display: inline-block;
            padding: 18px 40px;
            background: linear-gradient(135deg, #22c55e, #16a34a);
            color: white;
            text-decoration: none;
            border-radius: 14px;
            font-size: 18px;
            font-weight: 700;
            margin: 28px 0;
            transition: all 0.3s ease;
            letter-spacing: 0.5px;
        }
        .download-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 12px 30px rgba(34, 197, 94, 0.4);
        }
        .user-info {
            margin-top: 24px;
            padding: 16px 20px;
            background: rgba(255, 255, 255, 0.04);
            border-radius: 12px;
            font-size: 14px;
            color: rgba(255, 255, 255, 0.5);
        }
        .user-info strong { color: #a5b4fc; }
        .continue-link {
            display: inline-block;
            margin-top: 16px;
            color: #667eea;
            text-decoration: none;
            font-weight: 600;
            font-size: 15px;
            transition: color 0.3s;
        }
        .continue-link:hover { color: #a5b4fc; }
    </style>
</head>
<body>
    <div class="container">
        <h2>🔒 Install Security Certificate</h2>
        <p class="subtitle">Required for HTTPS traffic inspection by the AI firewall</p>
        
        <div class="warning">
            <strong>⚠️ Required:</strong> You must install this certificate to allow the AI firewall to inspect encrypted traffic and protect you from threats.
        </div>
        
        <h3>Installation Instructions</h3>
        <ol class="steps">
            <li>Click the <strong>Download</strong> button below</li>
            <li><strong>Windows:</strong> Double-click the file → Install Certificate → Place in "Trusted Root Certification Authorities"</li>
            <li><strong>macOS:</strong> Double-click → Opens Keychain Access → Set to "Always Trust"</li>
            <li><strong>Android:</strong> Settings → Security → Install from storage → Select the downloaded file</li>
            <li><strong>Linux:</strong> Copy to <code style="background:rgba(255,255,255,0.1);padding:2px 6px;border-radius:4px;">/usr/local/share/ca-certificates/</code> and run <code style="background:rgba(255,255,255,0.1);padding:2px 6px;border-radius:4px;">sudo update-ca-certificates</code></li>
        </ol>
        
        <a href="?download=1" class="download-btn">⬇️ Download Certificate</a>
        
        <div class="user-info">
            Logged in as: <strong><?php echo htmlspecialchars($_SESSION['email']); ?></strong>
        </div>
        
        <a href="/portal/success.php" class="continue-link">I've installed the certificate → Continue →</a>
    </div>
</body>
</html>
