@echo off
echo ========================================
echo  Koutu Animation with Native Export
echo ========================================
echo.
echo Starting Flutter app with native export capability...
echo.
echo To use the export feature:
echo 1. Click the "Capture Animation" button in the bottom-right
echo 2. Wait for the animation to complete (8 seconds)
echo 3. Click "Export" to download an HTML file with frames
echo 4. Open the HTML file to:
echo    - Play the animation
echo    - Download individual frames
echo    - Get instructions for creating GIF/MP4
echo.
echo ========================================
echo.

REM Run the app
flutter run -d chrome --web-port=5001 lib/main_with_export.dart