@echo off
echo [AI Firewall] Installing Windows Dependencies...

:: 1. Check for Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Python is not installed! Please install Python 3.10+ and add to PATH.
    pause
    exit /b
)

:: 2. Create Virtual Env
if not exist venv (
    echo Creating venv...
    python -m venv venv
)

:: 3. Install Requirements
call venv\Scripts\activate.bat
echo Installing libraries...
pip install -r requirements.txt
pip install pydivert
:: Windows specific pytorch (CPU)
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu

echo.
echo [SUCCESS] Installation Complete.
echo Please run 'start_windows.bat' as ADMINISTRATOR.
pause
