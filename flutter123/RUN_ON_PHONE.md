# Running Koutu Animation on Phone

## Option 1: Physical Android Phone (Easiest)

### Prerequisites:
1. Enable Developer Options on your phone:
   - Go to Settings → About Phone
   - Tap "Build Number" 7 times
   - Go back to Settings → Developer Options
   - Enable "USB Debugging"

2. Connect phone via USB cable

3. Run the animation:
```bash
cd flutter123
flutter devices  # Should show your phone
flutter run lib/main.dart
```

## Option 2: Physical iPhone

### Prerequisites:
1. Install Xcode on Mac
2. Connect iPhone via USB
3. Trust the computer on your iPhone

### Run:
```bash
cd flutter123
flutter devices  # Should show your iPhone
flutter run lib/main.dart
```

## Option 3: Web Browser on Phone (Quickest)

### Steps:
1. Run the web version:
```bash
cd flutter123
flutter run -d chrome --web-port=5001 --web-hostname=0.0.0.0 lib/main.dart
```

2. Find your computer's IP address:
```bash
# Windows (in WSL)
ip addr | grep eth0

# Or try
hostname -I
```

3. On your phone's browser, go to:
```
http://YOUR_COMPUTER_IP:5001
```

## Option 4: Flutter Web + ngrok (Public URL)

### Steps:
1. Install ngrok:
```bash
# Download from https://ngrok.com/download
# Or use snap
sudo snap install ngrok
```

2. Run Flutter web:
```bash
cd flutter123
flutter run -d chrome --web-port=5001 lib/main.dart
```

3. In another terminal, expose it:
```bash
ngrok http 5001
```

4. Use the ngrok URL on your phone

## Option 5: Build APK (Android)

### Build and install:
```bash
cd flutter123

# Build APK
flutter build apk --release

# The APK will be at:
# build/app/outputs/flutter-apk/app-release.apk

# Transfer to phone and install
```

## Option 6: Using Expo-like Services

### 1. **Codemagic** (CI/CD for Flutter)
- Push code to GitHub ✓ (already done)
- Sign up at codemagic.io
- Connect your repo
- Build and distribute to testers

### 2. **Firebase App Distribution**
```bash
# Install Firebase CLI
npm install -g firebase-tools

# Setup
firebase login
cd flutter123
flutterfire configure

# Build and distribute
flutter build apk
firebase appdistribution:distribute build/app/outputs/flutter-apk/app-release.apk \
  --app YOUR_APP_ID \
  --groups testers
```

### 3. **TestFlight** (iOS)
- Requires Apple Developer account
- Build IPA file
- Upload to App Store Connect
- Distribute via TestFlight

## Quick Start (Recommended)

For immediate testing on your phone, use **Option 3** (Web Browser):

```bash
# In your flutter123 directory
flutter run -d chrome --web-port=5001 --web-hostname=0.0.0.0 lib/main_with_export.dart

# Find your IP (example: 192.168.1.100)
ip addr | grep inet

# On phone browser: http://192.168.1.100:5001
```

## Tips:
- Make sure phone and computer are on same WiFi network
- Disable firewall temporarily if connection fails
- For better performance, use physical device over web
- The animation with export feature works best in Chrome