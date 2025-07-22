@echo off
echo.
echo 🚀 Running Koutu Animation with Auto Port Selection
echo =================================================
echo.

:: Get IP address
set IP=
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"IPv4 Address" ^| findstr /v "127.0.0.1"') do (
    for /f "tokens=* delims= " %%b in ("%%a") do (
        set IP=%%b
        goto :found
    )
)
:found

:: Try different ports
echo Trying different ports...
set PORTS=8090 8091 8092 3000 3001 5000 5001 9000 9001

for %%p in (%PORTS%) do (
    echo Trying port %%p...
    netstat -an | findstr :%%p >nul
    if errorlevel 1 (
        echo Port %%p is available!
        set PORT=%%p
        goto :run
    )
)

:: If all ports are taken, use a random high port
set /a PORT=%RANDOM% + 30000
echo Using random port %PORT%

:run
echo.
echo 💻 To view on THIS computer:
echo    http://localhost:%PORT%
echo.
echo 📱 To view on your PHONE:
if defined IP (
    echo    http://%IP%:%PORT%
) else (
    echo    http://[YOUR-IP]:%PORT%
)
echo.
echo Starting Flutter on port %PORT%...
echo Press Ctrl+C to stop
echo.

flutter run -d chrome --web-port=%PORT% --release lib/main_with_export.dart