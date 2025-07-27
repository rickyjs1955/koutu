@echo off
setlocal enabledelayedexpansion

:: Enable ANSI escape sequences for better animations
for /f "tokens=3" %%a in ('ver') do set version=%%a
set version=%version:.=%

:: 3D Rotating Cube Animation Function
:ShowRotatingCube
cls
echo.
echo                     K O U T U   3 D   B U I L D E R
echo.
:: Frame 1
echo                            +--------+
echo                           /        /^|
echo                          /        / ^|
echo                         +--------+  ^|
echo                         ^|        ^|  ^|
echo                         ^|  KOUTU ^|  +
echo                         ^|        ^| /
echo                         ^|        ^|/
echo                         +--------+
timeout /t 1 /nobreak > nul
cls
echo.
echo                     K O U T U   3 D   B U I L D E R
echo.
:: Frame 2
echo                           +--------+
echo                          /^|       /^|
echo                         + ^|      + ^|
echo                         ^| +------^|-+
echo                         ^|/       ^|/
echo                         +  KOUTU +
echo                          ^|       ^|
echo                          ^|       ^|
echo                          +-------+
timeout /t 1 /nobreak > nul
cls
echo.
echo                     K O U T U   3 D   B U I L D E R
echo.
:: Frame 3
echo                         +--------+
echo                         ^|^        ^\
echo                         ^| ^        ^\
echo                         ^|  +--------+
echo                         ^| /  KOUTU /
echo                         +/         /
echo                          ^\        /
echo                           ^\      /
echo                            +----+
timeout /t 1 /nobreak > nul
goto :eof

:: Call the rotating cube animation
call :ShowRotatingCube

:: Main Menu with 3D effect
cls
color 0A
echo.
echo          ╔════════════════════════════════════════════════╗
echo         ╔╝                                                ╚╗
echo        ╔╝     K O U T U   3 D   B U I L D   M E N U      ╚╗
echo       ╔╝                                                    ╚╗
echo      ╔╝  ┌─────────────────────────────────────────────┐   ╚╗
echo     ╔╝   │                                             │    ╚╗
echo    ╔╝    │  [1] Development Mode                       │     ╚╗
echo   ╔╝     │      • Hot Reload Enabled                   │      ╚╗
echo  ╔╝      │      • Desktop Only                         │       ╚╗
echo ╔╝       │      • Port: 5001                           │        ╚╗
echo ╚╗       │                                             │        ╔╝
echo  ╚╗      │  [2] Production Mode                        │       ╔╝
echo   ╚╗     │      • Optimized Build                      │      ╔╝
echo    ╚╗    │      • Multi-Device Support                 │     ╔╝
echo     ╚╗   │      • Port: 5001                           │    ╔╝
echo      ╚╗  └─────────────────────────────────────────────┘   ╔╝
echo       ╚╗                                                    ╔╝
echo        ╚╗                                                  ╔╝
echo         ╚╗                                                ╔╝
echo          ╚════════════════════════════════════════════════╝
echo.

set /p mode="          Enter your choice [1-2]: "

if "%mode%"=="1" (
    cls
    color 0B
    :: 3D Loading Animation for Dev Mode
    echo.
    echo    Starting Development Mode...
    echo.
    for /l %%i in (1,1,5) do (
        cls
        echo.
        echo    Starting Development Mode...
        echo.
        if %%i==1 (
            echo            ┌─┐
            echo            │ │
            echo            └─┘
        ) else if %%i==2 (
            echo          ┌─────┐
            echo         ╱│     │╲
            echo        ╱ │     │ ╲
            echo       ╱  └─────┘  ╲
            echo      ╱             ╲
            echo     └───────────────┘
        ) else if %%i==3 (
            echo        ┌───────────┐
            echo       ╱│           │╲
            echo      ╱ │    DEV    │ ╲
            echo     ╱  │   MODE    │  ╲
            echo    ╱   └───────────┘   ╲
            echo   └─────────────────────┘
        ) else if %%i==4 (
            echo      ┌─────────────────┐
            echo     ╱│                 │╲
            echo    ╱ │   LOADING...    │ ╲
            echo   ╱  │  ▓▓▓▓▓░░░░░    │  ╲
            echo  ╱   └─────────────────┘   ╲
            echo └───────────────────────────┘
        ) else if %%i==5 (
            echo    ┌───────────────────────┐
            echo   ╱│                       │╲
            echo  ╱ │    HOT RELOAD: ON     │ ╲
            echo ╱  │    PORT: 5001         │  ╲
            echo╱   │  ▓▓▓▓▓▓▓▓▓▓▓▓       │   ╲
            echo╲   └───────────────────────┘   ╱
            echo ╲                             ╱
            echo  ╲───────────────────────────╱
        )
        timeout /t 1 /nobreak > nul
    )
    
    echo.
    echo    📡 Flutter development server starting...
    echo.
    echo    🌐 Access URL: http://localhost:5001
    echo.
    echo    💡 Press Ctrl+C to stop
    echo.
    flutter run -d chrome --web-port=5001
    
) else if "%mode%"=="2" (
    cls
    color 0C
    :: 3D Building Animation for Production Mode
    echo.
    echo    Building Production Version...
    echo.
    
    :: Spinning gear animation
    set "frames[0]=     ╱───╲     "
    set "frames[1]=    ╱─────╲    "
    set "frames[2]=   │───────│   "
    set "frames[3]=    ╲─────╱    "
    set "frames[4]=     ╲───╱     "
    
    for /l %%x in (1,1,3) do (
        for /l %%i in (0,1,4) do (
            cls
            echo.
            echo    Building Production Version...
            echo.
            echo         ┌─────────────┐
            echo        ╱               ╲
            echo       │   B U I L D    │
            echo       │                 │
            echo       │  !frames[%%i]!  │
            echo       │                 │
            echo       │   %%x of 3      │
            echo        ╲               ╱
            echo         └─────────────┘
            timeout /t 1 /nobreak > nul
        )
    )
    
    echo.
    echo    🔨 Compiling optimized build...
    call flutter build web --release
    
    cls
    echo.
    echo    🔍 Network Configuration Detected
    echo.
    :: 3D Network visualization
    echo           ╔═══════════════════╗
    echo          ╱                     ╲
    echo         ╱   YOUR IP ADDRESSES   ╲
    echo        ╱ ┌─────────────────────┐ ╲
    echo       ╱  │                     │  ╲
    
    set count=0
    for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"IPv4"') do (
        set /a count+=1
        set ip=%%a
        for /f "tokens=* delims= " %%b in ("!ip!") do set ip=%%b
        echo      ╱   │ [!count!] !ip!         ╱
    )
    
    echo     ╱    └─────────────────────┘    ╱
    echo    ╱                                 ╱
    echo   ╱═════════════════════════════════╱
    echo.
    
    cd build\web
    
    :: 3D Server Launch Animation
    echo    🚀 Launching Server...
    echo.
    for /l %%i in (1,1,4) do (
        cls
        echo.
        echo    🚀 Launching Server...
        echo.
        if %%i==1 (
            echo              ∧
            echo             ╱ ╲
            echo            ╱   ╲
            echo           │     │
            echo           │  🚀 │
            echo           └─────┘
        ) else if %%i==2 (
            echo            ∧
            echo           ╱ ╲
            echo          ╱   ╲
            echo         ╱     ╲
            echo        │   🚀  │
            echo        │ ░░░░░ │
            echo        └───────┘
        ) else if %%i==3 (
            echo          ∧
            echo         ╱ ╲
            echo        ╱ 🚀╲
            echo       ╱ ░░░ ╲
            echo      ╱ ░░░░░ ╲
            echo     │ ░░░░░░░ │
            echo     └─────────┘
        ) else if %%i==4 (
            echo        🚀
            echo       ░░░
            echo      ░░░░░
            echo     ░░░░░░░
            echo    ░░░░░░░░░
            echo   ░░░░░░░░░░░
            echo    ┌───────┐
            echo    │ :5001 │
            echo    └───────┘
        )
        timeout /t 1 /nobreak > nul
    )
    
    cls
    echo.
    echo    ╔═══════════════════════════════════════════════╗
    echo   ╱│                                               │╲
    echo  ╱ │          SERVER RUNNING ON PORT 5001         │ ╲
    echo ╱  │                                               │  ╲
    echo│   │  💻 Desktop: http://localhost:5001           │   │
    echo│   │  📱 Mobile:  http://[YOUR-IP]:5001           │   │
    echo│   │                                               │   │
    echo╲   │  ⚠️  Devices must be on same WiFi network    │   ╱
    echo ╲  │                                               │  ╱
    echo  ╲ │  🛑 Press Ctrl+C to stop                     │ ╱
    echo   ╲│                                               │╱
    echo    ╚═══════════════════════════════════════════════╝
    echo.
    
    python -m http.server 5001 --bind 0.0.0.0
    
) else (
    cls
    color 04
    :: 3D Error Animation
    for /l %%i in (1,1,3) do (
        cls
        echo.
        if %%i==1 (
            echo         ╔═══════╗
            echo        ╱│  ⚠️   │╲
            echo       ╱ │ ERROR │ ╲
            echo      ╱  ╚═══════╝  ╲
            echo     ╱               ╲
            echo    └─────────────────┘
        ) else if %%i==2 (
            echo      ╔═════════════╗
            echo     ╱│      ⚠️      │╲
            echo    ╱ │    ERROR    │ ╲
            echo   ╱  │             │  ╲
            echo  ╱   ╚═════════════╝   ╲
            echo └───────────────────────┘
        ) else (
            echo    ╔═══════════════════╗
            echo   ╱│        ⚠️         │╲
            echo  ╱ │      ERROR       │ ╲
            echo ╱  │  Invalid choice  │  ╲
            echo│   │   Select 1 or 2  │   │
            echo╲   ╚═══════════════════╝   ╱
            echo ╲                         ╱
            echo  ╲───────────────────────╱
        )
        timeout /t 1 /nobreak > nul
    )
    timeout /t 2 /nobreak > nul
)

color 07
endlocal