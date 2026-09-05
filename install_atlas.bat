@echo off
setlocal enabledelayedexpansion
title ATLAS Automated 1-Click Installer

echo =======================================================================
echo          ATLAS BEHAVIORAL CYBER-INTELLIGENCE PLATFORM
echo                    Automated Windows Installer
echo =======================================================================
echo.

:: 1. Check for Administrative Privileges and Elevate if Needed
net session >nul 2>&1
if not %errorLevel% == 0 (
    echo [*] Requesting Administrator Privileges for OS Firewall and ETW access...
    powershell -Command "Start-Process cmd -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

echo [+] Running with Administrative Privileges.
cd /d "%~dp0"

:: 2. Verify Python Installation
python --version >nul 2>&1
if not %errorLevel% == 0 (
    echo.
    echo [-] ERROR: Python 3.10+ is not found in your PATH!
    echo     Please install Python from https://www.python.org/downloads/
    echo     Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

echo [+] Detected Python runtime.

:: 3. Create and Activate Virtual Environment (.venv)
if not exist ".venv" (
    echo [*] Creating isolated Python virtual environment (.venv)...
    python -m venv .venv
)

if exist ".venv\Scripts\activate.bat" (
    echo [*] Activating virtual environment...
    call .venv\Scripts\activate.bat
)

:: 4. Upgrade Pip and Install Dependencies
echo [*] Upgrading pip...
python -m pip install --upgrade pip --quiet

echo [*] Installing dependencies from requirements.txt...
python -m pip install -r requirements.txt --quiet --no-warn-script-location

:: 5. Execute Multi-Stage Environment Setup Script
echo.
python setup_environment.py

:: 6. Create Desktop Shortcut
echo [*] Creating Desktop Shortcut...
set "SHORTCUT_PATH=%USERPROFILE%\Desktop\ATLAS Security Platform.lnk"
set "TARGET_PATH=%~dp0start_atlas.bat"
set "ICON_PATH=%~dp0frontend\favicon.ico"

powershell -Command "$s=(New-Object -COM WScript.Shell).CreateShortcut('%SHORTCUT_PATH%'); $s.TargetPath='%TARGET_PATH%'; $s.WorkingDirectory='%~dp0'; $s.Description='ATLAS Behavioral Cyber-Intelligence Platform'; $s.Save()"

if exist "%SHORTCUT_PATH%" (
    echo [+] Created Desktop Shortcut: "%SHORTCUT_PATH%"
)

echo.
echo =======================================================================
echo [+] INSTALLATION COMPLETE!
echo.
echo     You can now launch ATLAS anytime by:
echo     1. Double-clicking the "ATLAS Security Platform" shortcut on your Desktop
echo     2. Or running "start_atlas.bat" in this folder
echo =======================================================================
echo.
pause
