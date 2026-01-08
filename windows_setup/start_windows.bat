@echo off
:: Check for Admin Privileges (Required for WinDivert)
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] This script requires Administrator privileges.
    echo Right-click and select "Run as administrator".
    pause
    exit /b
)

echo [AI Firewall] Starting Services...
call venv\Scripts\activate.bat

:: 1. Start AI Services (Background)
start "Master AI" python -m uvicorn master_ai.orchestrator:app --host 0.0.0.0 --port 8000
start "Image Service" python -m uvicorn image_service.main:app --host 0.0.0.0 --port 8001
start "Doc Service" python -m uvicorn document_service.main:app --host 0.0.0.0 --port 8002
start "Text Service" python -m uvicorn text_service.main:app --host 0.0.0.0 --port 8003

:: 2. Start Gateway (Mitmproxy)
echo Starting Gateway Proxy on 8080...
start "Gateway" mitmdump -s gateway/proxy.py --allow-hosts ".*" --set block_global=false

:: 3. Start Network Inspector (WinDivert)
echo Starting Network Inspector...
python windows_setup/network_inspector.py

pause
