@echo off
REM Starts CyberQuant AI for this laptop and every device on the same Wi-Fi.
cd /d "%~dp0"
if not exist .venv (
  python -m venv .venv
  .venv\Scripts\python -m pip install -r requirements.txt
)
REM Allow other devices through Windows Firewall (needs one-time admin approval; harmless if skipped)
netsh advfirewall firewall show rule name="CyberQuant AI" >nul 2>&1 || powershell -NoProfile -Command "Start-Process netsh -Verb RunAs -ArgumentList 'advfirewall firewall add rule name=\"CyberQuant AI\" dir=in action=allow protocol=TCP localport=8000 profile=private,domain'"
.venv\Scripts\python serve.py
pause
