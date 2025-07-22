@echo off
echo 🌟 Applying Full Animation Configuration
echo ======================================
echo.

echo Backing up current index.html...
copy web\index.html web\index_backup.html >nul 2>&1

echo Applying full animation index.html...
copy web\index_full.html web\index.html >nul 2>&1

echo.
echo ✅ Full animation configuration applied!
echo.
echo Now run:
echo   .\build_full_animation.bat
echo.
echo This will build with the stunning wardrobe animation
echo that includes particle effects, light beams, and clothing reveal.
echo.
pause