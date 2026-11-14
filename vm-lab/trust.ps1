foreach ($u in "https://www.microsoft.com/","https://client.wns.windows.com/","https://evilmicrosoft.com/","https://example.com/") {
  $c = & curl.exe -s -m 25 --ssl-no-revoke -o NUL -w "%{http_code} issuer-check" $u 2>&1
  "$u -> $c"
}
