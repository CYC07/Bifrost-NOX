1..5 | ForEach-Object {
  $c = & curl.exe -s -m 40 --ssl-no-revoke -o NUL -w "%{http_code} t=%{time_total}s" "https://httpbin.org/get?q=hello&page=2" 2>&1
  "try $_ -> $c"
}
