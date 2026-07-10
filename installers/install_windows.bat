@echo off
REM ============================================================
REM WOLFSTRIKE Windows Installer
REM Author: ATHEX BLACK HAT
REM Team: Wolf Intelligence PK
REM Version: 1.0.0
REM ============================================================

setlocal enabledelayedexpansion

set RED=[91m
set GREEN=[92m
set YELLOW=[93m
set BLUE=[94m
set CYAN=[96m
set NC=[0m

set INSTALL_DIR=%USERPROFILE%\wolfstrike
set CONFIG_DIR=%APPDATA%\WolfStrike
set DATA_DIR=%LOCALAPPDATA%\WolfStrike

echo %CYAN%
echo ============================================================
echo   WOLFSTRIKE v1.0.0 - Windows Installer
echo   Wolf Intelligence PK ^| ATHEX BLACK HAT
echo ============================================================
echo %NC%

echo %BLUE%[*] Checking Python installation...%NC%

where python >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo %RED%[-] Python not found%NC%
    echo %YELLOW%[!] Please install Python 3.10 or higher from https://www.python.org/downloads/%NC%
    echo %YELLOW%[!] Make sure to check "Add Python to PATH" during installation%NC%
    pause
    exit /b 1
)

for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set PYTHON_VERSION=%%v
echo %GREEN%[+] Python %PYTHON_VERSION% found%NC%

echo %BLUE%[*] Checking pip installation...%NC%
where pip >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo %RED%[-] pip not found%NC%
    echo %YELLOW%[!] Run: python -m ensurepip --upgrade%NC%
    pause
    exit /b 1
)
echo %GREEN%[+] pip found%NC%

echo %BLUE%[*] Creating directories...%NC%
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
if not exist "%CONFIG_DIR%" mkdir "%CONFIG_DIR%"
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"
if not exist "%DATA_DIR%\logs" mkdir "%DATA_DIR%\logs"
if not exist "%DATA_DIR%\reports" mkdir "%DATA_DIR%\reports"
echo %GREEN%[+] Directories created%NC%

echo %BLUE%[*] Installing Python dependencies...%NC%
cd /d "%INSTALL_DIR%"

if exist "requirements.txt" (
    python -m pip install --upgrade pip
    pip install -r requirements.txt
    echo %GREEN%[+] Python dependencies installed%NC%
) else (
    echo %YELLOW%[!] requirements.txt not found%NC%
    echo %YELLOW%[!] Installing core dependencies...%NC%
    pip install requests beautifulsoup4 dnspython rich PyYAML urllib3 certifi
)

echo %BLUE%[*] Creating launcher...%NC%
set LAUNCHER=%INSTALL_DIR%\wolfstrike.bat
(
    echo @echo off
    echo cd /d "%INSTALL_DIR%"
    echo python wolfstrike.py %%*
) > "%LAUNCHER%"

set PATH_SCRIPT=%INSTALL_DIR%\add_to_path.ps1
(
    echo $userPath = [Environment]::GetEnvironmentVariable^("Path", "User"^)
    echo if ^($userPath -notlike "*%INSTALL_DIR%*"^) {
    echo     [Environment]::SetEnvironmentVariable^("Path", "$userPath;%INSTALL_DIR%", "User"^)
    echo     Write-Host "Added to PATH"
    echo }
) > "%PATH_SCRIPT%"

echo %GREEN%[+] Launcher created%NC%

echo %BLUE%[*] Setting up configuration...%NC%
if not exist "%CONFIG_DIR%\settings.yaml" (
    if exist "%INSTALL_DIR%\config\settings.yaml" (
        copy "%INSTALL_DIR%\config\settings.yaml" "%CONFIG_DIR%\settings.yaml" >nul
        echo %GREEN%[+] Configuration file created%NC%
    )
)

echo.
echo %CYAN%============================================================%NC%
echo %GREEN%  WOLFSTRIKE Windows Installation Complete!%NC%
echo %CYAN%============================================================%NC%
echo.
echo   Installation Directory: %YELLOW%%INSTALL_DIR%%NC%
echo   Configuration:          %YELLOW%%CONFIG_DIR%%NC%
echo.
echo   Quick Start:
echo     %GREEN%wolfstrike --target example.com%NC%
echo     %GREEN%wolfstrike --interactive%NC%
echo     %GREEN%wolfstrike --help%NC%
echo.
echo   Optional: Run the following as Administrator to add to PATH:
echo     %GREEN%powershell -ExecutionPolicy Bypass -File "%PATH_SCRIPT%" %NC%
echo.
echo   %BLUE%Wolf Intelligence PK ^| ATHEX BLACK HAT%NC%
echo.

pause
exit /b 0