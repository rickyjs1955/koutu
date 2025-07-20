@echo off
echo Starting Koutu Fashion AI App...
echo.
echo Creating asset directories...
mkdir assets\images\logo 2>nul
mkdir assets\images\onboarding 2>nul
mkdir assets\images\placeholders 2>nul
mkdir assets\animations 2>nul
mkdir assets\fonts 2>nul

echo.
echo Getting dependencies...
call flutter pub get

echo.
echo Starting Flutter web server...
echo The app will open at http://localhost:5000
echo.
echo Press Ctrl+C to stop the server
echo.

call flutter run -d chrome --web-port=5000