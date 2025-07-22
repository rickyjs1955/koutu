@echo off
echo 🔍 Checking Flutter Version and Building
echo =======================================
echo.

echo Your Flutter version:
flutter --version
echo.

echo Available build options:
flutter build web -h | findstr /i "renderer"
echo.

echo Building standard web release...
flutter build web --release

echo.
echo Starting server...
echo 💻 Local: http://localhost:8085
echo 📱 Phone: http://192.168.1.126:8085
echo.
echo 📱 Mobile Tips:
echo - Wait 10-15 seconds for loading
echo - Try refreshing if stuck on "loading"
echo - Clear browser cache if needed
echo.

cd build\web
python -m http.server 8085 --bind 0.0.0.0