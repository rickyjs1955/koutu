@echo off
echo Starting test server...
echo ======================
echo.
echo Opening test URLs in your browser:
echo.

cd build\web

echo 1. Opening simple test page...
start http://localhost:8080/simple_test.html

echo 2. Opening main app...
start http://localhost:8080/

echo.
echo Starting Python HTTP server on port 8080...
echo Press Ctrl+C to stop the server
echo.
python -m http.server 8080