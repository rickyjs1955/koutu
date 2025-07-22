@echo off
echo ========================================
echo  KOUTU Animation Recording Script
echo ========================================
echo.

echo Step 1: Starting Flutter app...
start cmd /k "cd /d %~dp0 && flutter run -d chrome --web-port=5001"

echo.
echo Waiting for app to load...
timeout /t 5 /nobreak > nul

echo.
echo ========================================
echo  RECORDING INSTRUCTIONS:
echo ========================================
echo.
echo 1. The Flutter app should now be open in Chrome
echo 2. Make the browser window fullscreen (F11)
echo 3. Use one of these methods to record:
echo.
echo    OPTION A - Windows Game Bar (Easiest):
echo    - Press Win + Alt + R to start recording
echo    - Wait 8-10 seconds for full animation
echo    - Press Win + Alt + R again to stop
echo    - Video saved in: Videos\Captures folder
echo.
echo    OPTION B - OBS Studio:
echo    - Open OBS Studio
echo    - Add Window Capture source
echo    - Select Chrome window
echo    - Click "Start Recording"
echo    - Wait for animation
echo    - Click "Stop Recording"
echo.
echo    OPTION C - Browser Extension:
echo    - Use Loom, Screencastify, or similar
echo.
echo ========================================
echo.
pause