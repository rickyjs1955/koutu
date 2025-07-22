@echo off
echo Checking Flutter Build Output
echo =============================
echo.

echo Flutter version:
call flutter --version
echo.

echo Checking build\web directory:
dir build\web
echo.

echo Checking index.html content (first 20 lines):
type build\web\index.html | more +0 /E +20
echo.

echo Checking if main.dart.js exists:
if exist build\web\main.dart.js (
    echo ✓ main.dart.js found
    echo Size: 
    for %%A in (build\web\main.dart.js) do echo %%~zA bytes
) else (
    echo ✗ main.dart.js NOT FOUND - This is the problem!
)
echo.

echo Checking flutter.js:
if exist build\web\flutter.js (
    echo ✓ flutter.js found
) else (
    echo ✗ flutter.js NOT FOUND
)
echo.

echo Checking flutter_bootstrap.js:
if exist build\web\flutter_bootstrap.js (
    echo ✓ flutter_bootstrap.js found
) else (
    echo ✗ flutter_bootstrap.js NOT FOUND
)
echo.

pause