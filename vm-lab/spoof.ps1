"--- genuine: real microsoft IP"
& curl.exe -s -m 25 --ssl-no-revoke -o NUL -w "%{http_code}`n" https://www.microsoft.com/ 2>&1
"--- spoof: SNI/Host www.microsoft.com but connect to 93.184.216.34 (not Microsoft)"
& curl.exe -s -m 25 --ssl-no-revoke --connect-to www.microsoft.com:443:93.184.216.34:443 -o NUL -w "%{http_code} exit=$LASTEXITCODE`n" https://www.microsoft.com/ 2>&1
"exit: $LASTEXITCODE"
