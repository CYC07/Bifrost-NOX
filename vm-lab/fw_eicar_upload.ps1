$a = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EI' + 'CAR-STANDARD-ANTIVIRUS-'
$b = 'TEST-FILE!$H+H*'
$e = $a + $b
function Up($label, $url) {
  $o = $e | & curl.exe -sS -m 30 --ssl-no-revoke -o NUL -w "%{http_code}" -X POST $url -F "file=@-;filename=eicar.com" 2>&1 | Out-String
  "{0,-34} -> {1}" -f $label, ($o.Trim() -replace "\s+"," ")
}
Up "EICAR multipart upload (HTTP)"  "http://httpbin.org/post"
Up "EICAR multipart upload (HTTPS)" "https://httpbin.org/post"
$o = $e | & curl.exe -sS -m 30 --ssl-no-revoke -o NUL -w "%{http_code}" -X POST http://httpbin.org/post -H "Content-Type: application/octet-stream" --data-binary "@-" 2>&1 | Out-String
"{0,-34} -> {1}" -f "EICAR raw octet-stream (HTTP)", $o.Trim()
$o = "a perfectly ordinary text file" | & curl.exe -sS -m 30 --ssl-no-revoke -o NUL -w "%{http_code}" -X POST http://httpbin.org/post -F "file=@-;filename=notes.txt" 2>&1 | Out-String
"{0,-34} -> {1}" -f "benign multipart upload (HTTP)", $o.Trim()
