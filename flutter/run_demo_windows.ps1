# PowerShell script for Windows
Write-Host "🚀 Starting Koutu Wardrobe Demo..." -ForegroundColor Cyan
Write-Host ""
Write-Host "📱 This demo showcases a beautiful wardrobe management UI with:" -ForegroundColor Green
Write-Host "   ✨ Modern gradient design"
Write-Host "   🎨 Smooth animations"
Write-Host "   📊 Interactive categories"
Write-Host "   💫 Glass morphism effects"
Write-Host ""

Write-Host "🔧 Getting dependencies..." -ForegroundColor Yellow
flutter pub get

Write-Host ""
Write-Host "🌐 Starting Flutter web server..." -ForegroundColor Cyan
Write-Host "👉 Open http://localhost:5000 in your browser" -ForegroundColor Green
Write-Host ""
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Yellow
Write-Host ""

# Run Flutter web on port 5000 with the demo main file
flutter run -d chrome --web-port=5000 lib/demo_main.dart