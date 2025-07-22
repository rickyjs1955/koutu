# Quick Fix for Capture Issue

You're running the wrong file! The capture is stuck because the animation isn't restarting.

## Run this instead:

```bash
flutter run -d chrome --web-port=5001 lib/main_with_export.dart
```

Or on Windows:
```bash
flutter run -d chrome --web-port=5001 lib\main_with_export.dart
```

## Why it's stuck at 8%:

The current `main.dart` has an empty callback for `onAnimationComplete`, so the animation doesn't restart when you click capture. The `main_with_export.dart` has all the proper connections to restart the animation during capture.

## Alternative Quick Fix:

If you want to keep using the regular main.dart, run this instead to remove the export wrapper:

```bash
flutter run -d chrome --web-port=5001
```

Then use the recording scripts (record_animation.bat) to capture the animation externally.