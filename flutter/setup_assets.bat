@echo off
echo Creating asset directories and placeholder files...

REM Create directories
mkdir assets\animations 2>nul
mkdir assets\fonts 2>nul
mkdir assets\images\logo 2>nul
mkdir assets\images\onboarding 2>nul
mkdir assets\images\placeholders 2>nul

REM Create placeholder font file (temporary)
echo This is a placeholder for Montserrat font > assets\fonts\Montserrat-Regular.ttf

REM Create placeholder images
echo. > assets\animations\placeholder.png
echo. > assets\images\logo\placeholder.png
echo. > assets\images\onboarding\placeholder.png
echo. > assets\images\placeholders\placeholder.png

echo.
echo Asset directories created!
echo Note: Replace the font file with actual Montserrat-Regular.ttf for production use.
echo.