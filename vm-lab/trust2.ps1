"--- wns verbose"; & curl.exe -sv -m 20 --ssl-no-revoke -o NUL https://client.wns.windows.com/ 2>&1 | Select-String "HTTP/|error|schannel|SSL|Connected|resolve" | Select-Object -First 8
"--- evil dns"; & curl.exe -s -m 15 -o NUL -w "%{http_code} exit-check" https://evilmicrosoft.com/ 2>&1
"--- ex"; $LASTEXITCODE
