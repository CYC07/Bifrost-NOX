"""Hand-written, independent evaluation probes for the WAF (no generator, no public corpus).

One data module read by the dataset builder (``test_holdout.jsonl``), the Colab notebook (through
that file), the ship gate's production-path replay and the tests, so the probe set cannot drift.

* ``PROBES``            - 25 small probes (15 benign, 10 attacks) written before the v2 data existed.
* ``REALISTIC_BENIGN``  - ~45 realistic benign bodies the v1 model wrongly blocks: shell command
                          lines, HTML, access-log lines, config files, markdown with code fences,
                          SQL a developer might paste, URLs with query strings.

All of it is clean-by-intent except the ten attack probes. Nothing here may contain a customer or
engagement name; keep the examples on example.com / RFC 5737 documentation addresses.
"""
from __future__ import annotations

import json

# (id, label, text). Labels are taxonomy labels; "clean" is benign.
PROBES: list[tuple[str, str, str]] = [
    ("json login (alice)", "clean", json.dumps({"username": "alice", "password": "hunter2"})),
    ("json login (email)", "clean", json.dumps({"email": "bob@example.com", "password": "S3cure!pass"})),
    # (the original probe script listed this one twice, identical to the line above; compact form here)
    ("json login compact", "clean", '{"username":"alice","password":"hunter2"}'),
    ("json register", "clean", json.dumps({"name": "Carol", "email": "c@example.com", "password": "pw123456", "age": 31})),
    ("json search", "clean", json.dumps({"query": "best pizza near me", "page": 2})),
    ("json token refresh", "clean", json.dumps({"refresh_token": "abc123def456", "grant_type": "refresh_token"})),
    ("json telemetry", "clean", json.dumps({"deviceId": "abc123", "events": [{"t": 1, "n": "heartbeat"}]})),
    ("json echo reply", "clean", '{"args": {}, "data": "", "files": {}, "form": {"username": "admin", "password": "secret123"}, "headers": {"Accept": "*/*", "Host": "httpbin.org"}, "url": "http://httpbin.org/post"}'),
    ("robots.txt", "clean", "User-agent: *\nDisallow: /admin\nSitemap: https://example.com/sitemap.xml"),
    ("form login", "clean", "username=admin&password=secret123&remember=true"),
    ("form search", "clean", "q=best pizza near me&sort=popularity"),
    ("form contact", "clean", "first_name=Michael&last_name=Chen&company=Acme%20Corp"),
    ("html snippet", "clean", "<html><body><h1>Welcome</h1><p>Hello, world</p></body></html>"),
    ("plain prose", "clean", "Please contact our support team if you have any questions."),
    ("url path", "clean", "GET /static/css/site.css?v=3 HTTP/1.1"),
    ("sqli or", "sqli", "id=1' OR '1'='1' --"),
    ("sqli union", "sqli", "id=1 UNION SELECT username, password FROM users--"),
    ("sqli json", "sqli", json.dumps({"username": "admin' OR '1'='1' --", "password": "x"})),
    ("xss script", "xss", "q=<script>alert(document.cookie)</script>"),
    ("xss img", "xss", "name=<img src=x onerror=alert(1)>"),
    ("traversal", "path_traversal", "file=../../../../etc/passwd"),
    ("cmdi", "command_injection", "host=127.0.0.1; cat /etc/passwd"),
    ("cmdi json", "command_injection", json.dumps({"ip": "8.8.8.8 && whoami"})),
    ("ssti", "ssti", "name={{7*7}}{{config.items()}}"),
    ("scanner", "scanner", "GET /wp-login.php?x=sqlmap HTTP/1.1\nUser-Agent: sqlmap/1.7"),
]

REALISTIC_BENIGN: list[tuple[str, str]] = [
    # --- shell command lines
    ("shell git", 'git commit -m "fix: handle empty config" && git push origin main'),
    ("shell pip", "pip install -r requirements.txt --upgrade && python -m pytest -q"),
    ("shell ssh", "ssh -i ~/.ssh/id_ed25519 deploy@staging.example.com 'cd /srv/app && git pull && systemctl restart app'"),
    ("shell docker", "docker run --rm -p 8080:80 -v $(pwd)/site:/usr/share/nginx/html:ro nginx:alpine"),
    ("shell backup", "tar -czf backup-2024-05-01.tar.gz /var/www/html && scp backup-2024-05-01.tar.gz backup@10.0.0.5:/backups/"),
    ("shell npm", "cd ~/projects/blog; npm run build; npm test | tee test.log"),
    ("shell path", 'export PATH="$HOME/.local/bin:$PATH" && echo $PATH'),
    ("shell find", 'find . -name "*.py" -not -path "./venv/*" | xargs grep -n "TODO"'),
    ("shell curl", "curl -s -H \"Authorization: Bearer $TOKEN\" 'https://api.example.com/v1/users?limit=10' | jq '.data[].name'"),
    ("shell logs", "ls -la /var/log/nginx/ && tail -n 50 /var/log/nginx/error.log"),
    # --- HTML pages and fragments
    ("html page", '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Dashboard</title>'
                  '<link rel="stylesheet" href="/static/css/site.css"></head><body><nav><a href="/">Home</a> '
                  '<a href="/about">About</a></nav><h1>Dashboard</h1><p>Welcome back, Dana.</p></body></html>'),
    ("html form", '<form action="/login" method="post"><label for="email">Email</label>'
                  '<input type="email" id="email" name="email"><button type="submit">Sign in</button></form>'),
    ("html script src", '<script src="/static/js/app.js" defer></script>'),
    ("html menu", '<ul class="menu"><li><a href="/products?category=shoes&sort=price">Shoes</a></li>'
                  '<li><a href="/products?category=bags&sort=price">Bags</a></li></ul>'),
    ("html card", '<div class="card"><img src="/img/avatar.png" alt="Avatar" width="64"><h2>Sam O\'Neil</h2>'
                  "<p>Joined March 2021</p></div>"),
    ("html table", "<table><tr><th>Name</th><th>Qty</th></tr><tr><td>Widget</td><td>12</td></tr></table>"),
    # --- access-log and application log lines
    ("log nginx get", '203.0.113.7 - - [12/Mar/2024:10:15:32 +0000] "GET /index.html HTTP/1.1" 200 5123 "-" '
                      '"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36"'),
    ("log nginx post", '198.51.100.23 - alice [12/Mar/2024:10:16:01 +0000] "POST /api/v1/orders HTTP/1.1" 201 342 '
                       '"https://shop.example.com/cart" "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X)"'),
    ("log nginx css", '192.0.2.44 - - [12/Mar/2024:10:17:45 +0000] "GET /static/css/site.css?v=3 HTTP/1.1" 304 0 "-" "curl/8.5.0"'),
    ("log java", "2024-03-12T10:20:11.532Z INFO  [http-nio-8080-exec-3] c.example.shop.OrderService - Order 4821 created for user 77 in 42 ms"),
    ("log sshd", "Mar 12 10:21:09 web01 sshd[2211]: Accepted publickey for deploy from 10.0.0.8 port 51322 ssh2"),
    ("log worker", "ERROR 2024-03-12 10:22:03,114 worker-2 Timeout while fetching https://api.example.com/v1/items?page=3&per_page=50 (attempt 2 of 3)"),
    # --- configuration
    ("config ini", "[database]\nhost = localhost\nport = 5432\nname = appdb\nuser = app\n\n[cache]\nttl = 300"),
    ("config yaml", "server:\n  port: 8080\n  host: 0.0.0.0\nlogging:\n  level: info\n  file: /var/log/app/app.log\nfeatures:\n  - search\n  - export"),
    ("config package json", '{"name": "my-app", "version": "1.4.2", "scripts": {"build": "webpack --mode production", '
                            '"test": "jest --coverage"}, "dependencies": {"express": "^4.18.2"}}'),
    ("config compose", "services:\n  web:\n    image: nginx:1.25\n    ports:\n      - \"8080:80\"\n    depends_on:\n      - api\n"
                       "  api:\n    build: ./api\n    environment:\n      - LOG_LEVEL=warn"),
    ("config env", "NODE_ENV=production\nPORT=3000\nLOG_LEVEL=warn\nAPI_BASE_URL=https://api.example.com"),
    ("config nginx", "server {\n  listen 80;\n  server_name example.com;\n  location / {\n    proxy_pass http://127.0.0.1:3000;\n  }\n}"),
    ("config cron", "0 3 * * * /usr/local/bin/backup.sh >> /var/log/backup.log 2>&1"),
    # --- markdown with code fences
    ("md setup", "## Setup\n\nInstall dependencies:\n\n```bash\nnpm install\nnpm run dev\n```\n\nThen open http://localhost:3000 in your browser."),
    ("md python", '### Example\n\n```python\ndef greet(name):\n    return f"Hello, {name}!"\n\nprint(greet("world"))\n```'),
    ("md sql", "Run this migration:\n\n```sql\nALTER TABLE users ADD COLUMN last_login TIMESTAMP;\n```\n"),
    ("md checklist", "- [ ] write tests\n- [x] update README\n- [ ] tag release v1.2.0"),
    # --- SQL a developer might paste
    ("sql select", "SELECT id, name, email FROM users WHERE created_at > '2024-01-01' ORDER BY created_at DESC LIMIT 20;"),
    ("sql insert", "INSERT INTO orders (user_id, total, status) VALUES (42, 99.50, 'pending');"),
    ("sql update", "UPDATE products SET stock = stock - 1 WHERE id = 17 AND stock > 0;"),
    ("sql index", "CREATE INDEX idx_orders_user ON orders (user_id, created_at);"),
    ("sql join", "SELECT o.id, c.name FROM orders o JOIN customers c ON c.id = o.customer_id WHERE o.status = 'shipped' "
                 "GROUP BY o.id, c.name HAVING COUNT(*) > 1;"),
    ("sql delete", "DELETE FROM sessions WHERE expires_at < NOW();"),
    # --- URLs with query strings
    ("url search", "https://www.example.com/search?q=wireless+headphones&category=electronics&page=2"),
    ("url product", "https://example.com/products/42?color=blue&size=M&utm_source=newsletter&utm_medium=email"),
    ("url api", "/api/v1/orders?status=shipped&limit=50&offset=100&sort=-created_at"),
    ("url map", "https://maps.example.com/place?lat=51.5074&lng=-0.1278&zoom=12"),
    ("url oauth", "https://auth.example.com/oauth/callback?code=4f3a9c1d&state=xyz123&redirect_uri=https%3A%2F%2Fapp.example.com%2Fhome"),
    ("url blog", "https://example.com/blog/2024/03/how-to-bake-sourdough?ref=homepage#comments"),
]


def probe_cases() -> list[dict]:
    """The 25 small probes as ``{name, label, text}`` dicts (label 'clean' for the 15 benign)."""
    return [{"name": n, "label": lab, "text": t} for n, lab, t in PROBES]


def benign_body_cases() -> list[dict]:
    """The realistic benign bodies as ``{name, label='clean', text}`` dicts."""
    return [{"name": n, "label": "clean", "text": t} for n, t in REALISTIC_BENIGN]


def all_texts() -> list[str]:
    return [t for _, _, t in PROBES] + [t for _, t in REALISTIC_BENIGN]
