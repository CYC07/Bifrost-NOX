foreach ($u in "https://client.wns.windows.com/","https://v10.events.data.microsoft.com/","https://login.live.com/") {
  $c = & curl.exe -s -m 25 --ssl-no-revoke -o NUL -w "%{http_code}" $u 2>&1
  "$u -> $c"
}
