@echo off
setlocal enabledelayedexpansion
title ATLAS Security Platform - Control Console

echo =======================================================================
echo              ATLAS BEHAVIORAL CYBER-INTELLIGENCE PLATFORM
echo                           Launcher Console
echo =======================================================================
echo.

cd /d "%~dp0"

:: 1. Check for Administrative Privileges and Elevate if Needed
net session >nul 2>&1
if not %errorLevel% == 0 (
    echo [*] Elevating to Administrator for Firewall and Live Telemetry access...
    powershell -Command "Start-Process cmd -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

:: 2. Activate Virtual Environment if available
if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
)

:: 3. Launch Flask Web Dashboard Server
echo [+] Launching ATLAS Visual Dashboard Server...
start "ATLAS Web Server" cmd /c "python web_app.py"

:: 4. Launch Live Telemetry & Threat Defense Agent
echo [+] Launching ATLAS Autonomous Security Agent...
start "ATLAS Agent Daemon" cmd /c "python atlas_agent.py"

:: 5. Wait for Services Initialization and Open Browser
echo [+] Initializing engines (waiting 3 seconds)...
timeout /t 3 /nobreak >nul

echo [+] Launching ATLAS Web UI in default browser...
start http://localhost:5000/

echo.
echo =======================================================================
echo [+] ATLAS PLATFORM RUNNING!
echo     Dashboard: http://localhost:5000
echo.
echo     Keep this window open while monitoring your system.
echo     Press any key to safely stop ATLAS background services and exit.
echo =======================================================================
pause >nul

:: Clean Shutdown
echo.
echo [*] Stopping ATLAS background services...
taskkill /fi "windowtitle eq ATLAS Web Server*" /t /f >nul 2>&1
taskkill /fi "windowtitle eq ATLAS Agent Daemon*" /t /f >nul 2>&1
echo [+] All ATLAS services stopped cleanly.
timeout /t 2 /nobreak >nul
