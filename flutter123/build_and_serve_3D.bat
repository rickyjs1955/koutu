@echo off
setlocal enabledelayedexpansion

:: 3D ASCII Art Header
echo.
echo      ___________________________________________
echo     /                                           /^|
echo    /   K O U T U   3 D   B U I L D E R        / ^|
echo   /___________________________________________/  ^|
echo   ^|                                           ^|  ^|
echo   ^|   [1] Dev Mode    (Hot Reload)           ^|  ^|
echo   ^|   [2] Production  (Phone + Desktop)      ^|  /
echo   ^|___________________________________________^|/
echo.
echo                    Choose wisely...
echo.

:: Color codes for enhanced visual
color 0A

set /p mode="   Enter your choice [1-2]: "

if "%mode%"=="1" (
    cls
    color 0B
    echo.
    echo    ╔═══════════════════════════════════════════╗
    echo    ║                                           ║
    echo    ║        DEVELOPMENT MODE ACTIVATED         ║
    echo    ║                                           ║
    echo    ║         ┌─────────────────────┐          ║
    echo    ║         │   HOT RELOAD: ON    │          ║
    echo    ║         │   PORT: 5001        │          ║
    echo    ║         │   DESKTOP ONLY      │          ║
    echo    ║         └─────────────────────┘          ║
    echo    ║                                           ║
    echo    ╚═══════════════════════════════════════════╝
    echo.
    echo    📡 Starting Flutter development server...
    echo.
    echo    🌐 Access points:
    echo    ┌──────────────────────────────────────────┐
    echo    │  LOCAL:  http://localhost:5001           │
    echo    └──────────────────────────────────────────┘
    echo.
    echo    💡 Press Ctrl+C to stop the server
    echo.
    timeout /t 3 /nobreak > nul
    flutter run -d chrome --web-port=5001
) else if "%mode%"=="2" (
    cls
    color 0C
    echo.
    echo    ╔═══════════════════════════════════════════╗
    echo    ║                                           ║
    echo    ║       PRODUCTION BUILD INITIATED          ║
    echo    ║                                           ║
    echo    ║         ┌─────────────────────┐          ║
    echo    ║         │   OPTIMIZED BUILD   │          ║
    echo    ║         │   PORT: 5001        │          ║
    echo    ║         │   MULTI-DEVICE      │          ║
    echo    ║         └─────────────────────┘          ║
    echo    ║                                           ║
    echo    ╚═══════════════════════════════════════════╝
    echo.
    echo    🔨 Building production version...
    echo    ┌──────────────────────────────────────────┐
    echo    │                                          │
    call flutter build web --release
    echo    │              BUILD COMPLETE              │
    echo    └──────────────────────────────────────────┘
    echo.
    
    echo    🔍 Detecting network configuration...
    echo.
    echo    ╔══════════════════════════════════════════╗
    echo    ║         YOUR IP ADDRESSES                ║
    echo    ╠══════════════════════════════════════════╣
    
    :: Get IP addresses with better formatting
    set count=0
    for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"IPv4"') do (
        set /a count+=1
        set ip=%%a
        :: Remove leading spaces
        for /f "tokens=* delims= " %%b in ("!ip!") do set ip=%%b
        echo    ║  [!count!] !ip!
    )
    echo    ╚══════════════════════════════════════════╝
    echo.
    
    cd build\web
    
    echo    🚀 Launching production server...
    echo.
    echo    ╔══════════════════════════════════════════╗
    echo    ║           ACCESS POINTS                  ║
    echo    ╠══════════════════════════════════════════╣
    echo    ║                                          ║
    echo    ║  💻 Desktop:                             ║
    echo    ║     http://localhost:5001                ║
    echo    ║                                          ║
    echo    ║  📱 Mobile devices:                      ║
    echo    ║     http://[YOUR-IP]:5001                ║
    echo    ║                                          ║
    echo    ║  ⚠️  Ensure same WiFi network!           ║
    echo    ║                                          ║
    echo    ╚══════════════════════════════════════════╝
    echo.
    echo    🛑 Press Ctrl+C to stop the server
    echo.
    
    :: Add a cool loading animation before starting server
    echo    Starting server
    for /l %%i in (1,1,3) do (
        <nul set /p =.
        timeout /t 1 /nobreak > nul
    )
    echo.
    echo.
    
    python -m http.server 5001 --bind 0.0.0.0
) else (
    cls
    color 04
    echo.
    echo    ╔══════════════════════════════════════════╗
    echo    ║                                          ║
    echo    ║            ⚠️  ERROR  ⚠️                  ║
    echo    ║                                          ║
    echo    ║     Invalid choice detected!             ║
    echo    ║                                          ║
    echo    ║     Please run again and select:         ║
    echo    ║        [1] for Development mode          ║
    echo    ║        [2] for Production mode           ║
    echo    ║                                          ║
    echo    ╚══════════════════════════════════════════╝
    echo.
    timeout /t 5
)

:: Reset color before exit
color 07
endlocal