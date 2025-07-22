@echo off
echo 🚀 Quick Deploy to Netlify
echo ========================
echo.

echo Step 1: Building app with full animation...
call .\build_full_animation.bat

echo.
echo Step 2: Your build is ready in build\web
echo.
echo Step 3: Deploy to Netlify:
echo   1. Open https://app.netlify.com/drop in your browser
echo   2. Drag the 'build\web' folder to the browser window
echo   3. Wait for upload to complete
echo   4. You'll get a URL like: https://amazing-koutu-123456.netlify.app
echo.
echo Step 4: Share the URL with anyone to access on mobile!
echo.
echo Opening Netlify Drop in your browser...
start https://app.netlify.com/drop
echo.
echo Also opening your build folder...
explorer build\web
echo.
pause