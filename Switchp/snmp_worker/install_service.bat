@echo off
:: SNMP Worker - Windows Service Installer
:: Run this script as Administrator

setlocal EnableDelayedExpansion

:: ── Locate python ─────────────────────────────────────────────────────────
set PYTHON=python
where python >nul 2>&1
if errorlevel 1 (
    set PYTHON=py
    where py >nul 2>&1
    if errorlevel 1 (
        echo ERROR: Python is not in PATH. Please install Python and add it to PATH.
        pause
        exit /b 1
    )
)

:: ── Move to the snmp_worker directory ─────────────────────────────────────
cd /d "%~dp0"

echo ============================================================
echo  SNMP Worker - Windows Service Manager
echo ============================================================
echo.
echo  1. Install and start service (auto-start on boot)
echo  2. Stop and remove service
echo  3. Show service status
echo  4. Install pywin32 (required once)
echo  5. Exit
echo.
set /p CHOICE= Select option [1-5]: 

if "%CHOICE%"=="1" goto INSTALL
if "%CHOICE%"=="2" goto REMOVE
if "%CHOICE%"=="3" goto STATUS
if "%CHOICE%"=="4" goto INSTALL_PYWIN32
if "%CHOICE%"=="5" exit /b 0

echo Invalid choice.
pause
exit /b 1

:INSTALL
echo.
echo [1/4] Installing Python dependencies (requirements.txt + pywin32)...
if exist "%~dp0requirements.txt" (
    %PYTHON% -m pip install -r "%~dp0requirements.txt" --quiet
    if errorlevel 1 (
        echo WARNING: Some packages from requirements.txt could not be installed.
        echo          Check the output above and install missing packages manually.
    )
)
%PYTHON% -m pip install pywin32 --quiet
%PYTHON% -m pywin32_postinstall -install >nul 2>&1

echo [2/4] Stopping existing service (if running or paused)...
:: Check if the service already exists
sc query SNMPWorker >nul 2>&1
if not errorlevel 1 (
    :: Service exists – stop it regardless of current state (RUNNING, PAUSED, etc.)
    sc stop SNMPWorker >nul 2>&1
    :: Brief wait for the SCM to process the stop request
    timeout /t 4 /nobreak >nul
    :: If still paused, resume then stop (some SCM versions need resume before stop)
    sc query SNMPWorker | findstr /i "PAUSED" >nul 2>&1
    if not errorlevel 1 (
        sc resume SNMPWorker >nul 2>&1
        timeout /t 2 /nobreak >nul
        sc stop SNMPWorker >nul 2>&1
        timeout /t 3 /nobreak >nul
    )
)

echo [3/4] Registering Windows Service...
%PYTHON% windows_service.py install
if errorlevel 1 (
    echo ERROR: Service installation failed. Run this script as Administrator.
    pause
    exit /b 1
)

echo [4/4] Setting service to auto-start and starting...
sc config SNMPWorker start= auto >nul
sc description SNMPWorker "Monitors network switches via SNMP for the Switchp dashboard." >nul

:: Use sc start — handles the case where service is stopped or freshly registered
sc start SNMPWorker >nul 2>&1

:: Poll for up to 20 seconds until STATE reaches RUNNING (4)
:: sc query STATE line format:  "        STATE              : 4  RUNNING"
:: tokens: 1=STATE  2=:  3=<numeric_code>  4=<text_label>
:: We compare against the numeric code (token 3).
set SVC_STATE=0
set /a POLL=0
:WAIT_START
timeout /t 2 /nobreak >nul
set /a POLL+=2
for /f "tokens=3" %%s in ('sc query SNMPWorker 2^>nul ^| findstr /c:"STATE"') do set SVC_STATE=%%s
if "%SVC_STATE%"=="4" goto START_OK
if "%SVC_STATE%"=="7" goto RESUME_PAUSED
:: State 1 = STOPPED — the service crashed immediately; no point waiting
if "%SVC_STATE%"=="1" goto START_FAILED
if %POLL% lss 20 goto WAIT_START

:START_FAILED
echo.
echo ERROR: Service stopped immediately (state code: %SVC_STATE%).
echo.
echo Possible causes:
echo   - worker.py or its dependencies could not be loaded
echo   - config\config.yml is missing or has invalid settings
echo   - Database is unreachable at startup
echo.
echo To diagnose: open Windows Event Viewer ^> Windows Logs ^> Application
echo and look for SNMPWorker errors. Also check:
echo   %~dp0logs\snmp_worker.log
echo.
sc query SNMPWorker
pause
exit /b 1

:RESUME_PAUSED
echo  Service is PAUSED – resuming...
sc resume SNMPWorker >nul 2>&1
timeout /t 2 /nobreak >nul

:START_OK
echo.
echo  Service is RUNNING.
echo  It will start automatically when Windows boots.
echo.
sc query SNMPWorker
pause
exit /b 0

:REMOVE
echo.
echo Stopping service...
sc stop SNMPWorker >nul 2>&1
timeout /t 3 /nobreak >nul
%PYTHON% windows_service.py remove
if errorlevel 1 (
    echo ERROR: Could not remove service. Run as Administrator.
) else (
    echo Service removed successfully.
)
pause
exit /b 0

:STATUS
echo.
sc query SNMPWorker
pause
exit /b 0

:INSTALL_PYWIN32
echo.
echo Installing pywin32...
%PYTHON% -m pip install pywin32
%PYTHON% -m pywin32_postinstall -install
echo Done.
pause
exit /b 0
