#!/bin/bash

echo "🚀 Running Koutu Animation for Phone Access"
echo "=========================================="
echo ""

# Get IP address
IP=$(hostname -I | awk '{print $1}')
if [ -z "$IP" ]; then
    IP=$(ip addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -1)
fi

echo "📱 To view on your phone:"
echo ""
echo "1. Make sure your phone is on the same WiFi network"
echo "2. Open your phone's browser"
echo "3. Go to: http://$IP:5001"
echo ""
echo "Starting Flutter web server..."
echo "Press Ctrl+C to stop"
echo ""

# Run Flutter with web server accessible from network
flutter run -d chrome --web-port=5001 --web-hostname=0.0.0.0 lib/main_with_export.dart