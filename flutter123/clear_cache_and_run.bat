@echo off
echo 🧹 Clearing Flutter Web Cache and Rebuilding
echo ===========================================
echo.

echo Step 1: Cleaning Flutter build cache...
flutter clean

echo.
echo Step 2: Getting packages...
flutter pub get

echo.
echo Step 3: Building fresh web version...
flutter build web --release --no-tree-shake-icons

echo.
echo Step 4: Copying test file...
copy test_static.html build\web\test.html

echo.
echo Step 5: Starting server...
echo.
echo 💻 Local: http://localhost:8085
echo 📱 Phone: http://192.168.1.126:8085
echo.
echo 🧪 First try: http://192.168.1.126:8085/test.html
echo    (This should show a simple HTML page)
echo.
echo 📱 Then try: http://192.168.1.126:8085
echo    (This is the Flutter app)
echo.

cd build\web
python -m http.server 8085 --bind 0.0.0.0