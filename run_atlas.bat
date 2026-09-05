@echo off
title ATLAS Orchestration Control Console
echo =======================================================================
echo              ATLAS BEHAVIORAL CYBER-INTELLIGENCE PLATFORM
echo =======================================================================
echo.
echo [!] NOTE: To enable local Windows Defender Firewall IP blocking,
echo     please ensure this command console is Run as Administrator.
echo.

:: Check for Administrative privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [+] Running with Administrative privileges. Firewall integration ACTIVE.
) else (
    echo [!] WARNING: Running without Administrative privileges.
    echo     Honeypot captures will show up on the dashboard, but local
    echo     firewall blocking rules will fail to register on OS level.
    echo     To fix this, close this window and right-click -> Run as Administrator.
)
echo.

echo [+] Launching ATLAS Dashboard Backend Server (Flask)...
start "ATLAS Dashboard Server" cmd /c "python web_app.py"

echo [+] Launching ATLAS Live EDR Telemetry & T-Pot Honeypot Agent...
start "ATLAS Live EDR & Honeypot Agent" cmd /c "python atlas_agent.py"

echo [+] Waiting 3 seconds for services initialization...
timeout /t 3 /nobreak >nul

echo [+] Launching ATLAS Visual Dashboard Console...
explorer "http://localhost:5000"

echo.
echo =======================================================================
echo [+] ATLAS platform successfully launched.
echo     Dashboard is running at: http://localhost:5000
echo.
echo     Keep this orchestration console open to monitor background actions.
echo     Press any key to stop all background windows and exit.
echo =======================================================================
pause >nul

:: Terminate flask and agent processes on console exit
echo [-] Cleaning up background processes...
taskkill /fi "windowtitle eq ATLAS Dashboard Server*" /t /f >nul 2>&1
taskkill /fi "windowtitle eq ATLAS Live EDR & Honeypot Agent*" /t /f >nul 2>&1
echo [+] Clean exit completed.
