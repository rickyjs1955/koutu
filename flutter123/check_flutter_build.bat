@echo off
echo Checking Flutter version and build options...
echo =========================================
echo.

echo Flutter version:
call flutter --version
echo.

echo Available web build options:
call flutter build web -h | findstr /i "renderer"
echo.

echo Testing basic web build:
call flutter build web --release
echo.

pause