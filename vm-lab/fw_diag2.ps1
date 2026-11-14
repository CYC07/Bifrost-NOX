"eicar file present: " + (Test-Path C:\fwlab\eicar.com.txt)
& curl.exe -sS -m 20 --ssl-no-revoke -o NUL -w "code=%{http_code}`n" -X POST http://httpbin.org/post -F "file=@C:\fwlab\eicar.com.txt;filename=eicar.com" 2>&1 | Out-String
(Get-MpComputerStatus -ErrorAction SilentlyContinue | Select-Object -ExpandProperty RealTimeProtectionEnabled)
