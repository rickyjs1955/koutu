#!/bin/bash

echo "🚀 Starting Koutu Wardrobe Demo..."
echo ""
echo "📱 This demo showcases a beautiful wardrobe management UI with:"
echo "   ✨ Modern gradient design"
echo "   🎨 Smooth animations"
echo "   📊 Interactive categories"
echo "   💫 Glass morphism effects"
echo ""

# Check if Flutter is in PATH
if ! command -v flutter &> /dev/null; then
    echo "❌ Flutter not found in PATH"
    echo "👉 Please ensure Flutter is installed and in your PATH"
    echo "   Visit: https://flutter.dev/docs/get-started/install"
    exit 1
fi

echo "🔧 Getting dependencies..."
flutter pub get

echo ""
echo "🌐 Starting Flutter web server..."
echo "👉 Open http://localhost:5000 in your browser"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

# Run Flutter web on port 5000 with the demo main file
flutter run -d chrome --web-port=5000 lib/demo_main.dart