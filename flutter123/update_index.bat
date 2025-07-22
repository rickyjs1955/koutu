@echo off
echo 📱 Updating index.html with animated loading screen
echo ================================================
echo.

echo Backing up current index.html...
copy web\index.html web\index_backup.html >nul 2>&1

echo Replacing with animated version...
copy web\index_animated.html web\index.html >nul 2>&1

echo.
echo ✅ Done! Your web/index.html now has a CSS-based loading animation.
echo.
echo This animation will show:
echo - Wardrobe doors opening
echo - KOUTU logo fading in
echo - Pure CSS animation (no JavaScript dependencies)
echo - Mobile-optimized sizing
echo.
echo To test, rebuild with any of your build scripts.
echo.
pause