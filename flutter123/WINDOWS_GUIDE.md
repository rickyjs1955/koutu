# Windows Guide for Koutu Animation

## Fixing the Android Build Error

Run this in PowerShell or Command Prompt:
```cmd
cd C:\Users\monmo\koutu\flutter123
fix_android_build.bat
```

This will create the missing Android configuration.

## Running on Phone (Windows)

### Option 1: Web Browser Method (Easiest)
```cmd
cd C:\Users\monmo\koutu\flutter123
run_on_phone.bat
```

### Option 2: Build APK
After fixing Android configuration:
```cmd
flutter build apk
```

The APK will be at: `build\app\outputs\flutter-apk\app-release.apk`

## Alternative: Manual Android Setup

If the fix script doesn't work:

1. Create a temporary Flutter project:
```cmd
cd C:\Users\monmo
flutter create temp_koutu
```

2. Copy the Android folder:
```cmd
xcopy /E /I temp_koutu\android C:\Users\monmo\koutu\flutter123\android
```

3. Clean and rebuild:
```cmd
cd C:\Users\monmo\koutu\flutter123
flutter clean
flutter pub get
flutter build apk
```

## Running Without Building APK

For quick testing, use the web version:
```cmd
run_on_phone.bat
```

Then open the displayed URL on your phone's browser (both devices must be on same WiFi).

## Troubleshooting

If you get "command not found" errors:
1. Make sure Flutter is in your PATH
2. Run `flutter doctor` to check installation
3. Use full Flutter path: `C:\path\to\flutter\bin\flutter build apk`