function Run($label, $a) {
  $o = & curl.exe @a 2>&1 | Out-String
  "{0,-30} {1}" -f $label, ($o.Trim() -replace "\s+"," ")
}
Run "https default"          @("-sS","-m","20","-o","NUL","-w","code=%{http_code}","https://example.org/")
Run "https --ssl-no-revoke"  @("-sS","-m","20","--ssl-no-revoke","-o","NUL","-w","code=%{http_code}","https://example.org/")
Run "https httpbin no-revoke" @("-sS","-m","20","--ssl-no-revoke","-o","NUL","-w","code=%{http_code}","https://httpbin.org/get")
"--- DNS ---"
foreach ($h in "www.eicar.org","secure.eicar.org","eicar.org") {
  try { $r = Resolve-DnsName $h -Type A -ErrorAction Stop | Where-Object Type -eq 'A' | Select-Object -First 1; "{0} -> {1}" -f $h, $r.IPAddress } catch { "{0} -> FAIL {1}" -f $h, $_.Exception.Message }
}
