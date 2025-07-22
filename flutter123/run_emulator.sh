#!/bin/bash

echo "🚀 Running Koutu Animation in Emulator"
echo "===================================="
echo ""

# Check available devices
echo "Checking available devices..."
flutter devices

echo ""
echo "Options to run the animation:"
echo "1. flutter run -d chrome lib/main_with_export.dart    # Web browser"
echo "2. flutter run lib/main_with_export.dart              # Default device"
echo "3. flutter run -d <device_id> lib/main_with_export.dart  # Specific device"
echo ""
echo "To set up Android emulator:"
echo "- Install Android Studio"
echo "- Open AVD Manager"
echo "- Create a virtual device"
echo "- Or use: flutter emulators --create --name my_emulator"
echo ""
echo "Starting on default available device..."
flutter run lib/main_with_export.dart