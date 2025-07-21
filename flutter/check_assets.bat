@echo off
echo Checking assets structure...
echo.
echo Checking directories:
if exist assets\images\logo echo [OK] assets\images\logo exists
if not exist assets\images\logo echo [MISSING] assets\images\logo
if exist assets\images\onboarding echo [OK] assets\images\onboarding exists
if not exist assets\images\onboarding echo [MISSING] assets\images\onboarding
if exist assets\images\placeholders echo [OK] assets\images\placeholders exists
if not exist assets\images\placeholders echo [MISSING] assets\images\placeholders
if exist assets\animations echo [OK] assets\animations exists
if not exist assets\animations echo [MISSING] assets\animations
if exist assets\fonts echo [OK] assets\fonts exists
if not exist assets\fonts echo [MISSING] assets\fonts
echo.
echo Checking files:
if exist assets\images\logo\placeholder.png echo [OK] assets\images\logo\placeholder.png exists
if not exist assets\images\logo\placeholder.png echo [MISSING] assets\images\logo\placeholder.png
if exist assets\fonts\Montserrat-Regular.ttf echo [OK] assets\fonts\Montserrat-Regular.ttf exists
if not exist assets\fonts\Montserrat-Regular.ttf echo [MISSING] assets\fonts\Montserrat-Regular.ttf
echo.
pause