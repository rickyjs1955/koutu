#!/bin/bash

echo "🚀 Starting Koutu Fashion AI App..."
echo ""
echo "📱 Features:"
echo "   ✨ AI-powered garment capture with polygon drawing"
echo "   🎨 Digital wardrobe management"
echo "   🤖 AI outfit builder"
echo "   📊 Fashion analytics"
echo ""

cd /home/monmonmic/koutu/flutter

echo "🔧 Getting dependencies..."
flutter pub get

echo ""
echo "🌐 Starting Flutter web server..."
echo "👉 The app will open automatically in your browser"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

# Run Flutter web
flutter run -d chrome --web-port=5000