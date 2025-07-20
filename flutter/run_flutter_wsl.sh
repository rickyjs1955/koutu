#!/bin/bash

# Run Flutter web server in WSL
echo "Starting Koutu Fashion AI App in WSL..."
echo ""

# Create asset directories
mkdir -p assets/images/logo
mkdir -p assets/images/onboarding
mkdir -p assets/images/placeholders
mkdir -p assets/animations
mkdir -p assets/fonts

echo "Getting dependencies..."
# Use Windows Flutter from WSL
/mnt/c/Users/monmo/flutter/bin/flutter.bat pub get

echo ""
echo "Starting Flutter web server..."
echo "The app will open at http://localhost:5000"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

# Run Flutter web with Windows Flutter
/mnt/c/Users/monmo/flutter/bin/flutter.bat run -d chrome --web-port=5000