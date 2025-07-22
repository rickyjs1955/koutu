# Recording Flutter Animation to MP4

## Method 1: Using OBS Studio (Recommended for Quality)

1. **Install OBS Studio** (free screen recording software)
   - Download from: https://obsproject.com/

2. **Setup OBS**:
   - Add Source → Window Capture → Select Chrome/Browser window
   - Set Canvas Resolution: 1920x1080 (or your preferred size)
   - Set Output Format: MP4
   - Set FPS: 60 (for smooth animation)

3. **Record**:
   - Run Flutter app: `flutter run -d chrome --web-port=5001`
   - Open browser in fullscreen (F11)
   - Start OBS recording
   - Let animation play through
   - Stop recording after animation completes

## Method 2: Using FFmpeg with Puppeteer (Automated)

Create a Node.js script to automate the recording:

```javascript
// record_animation.js
const puppeteer = require('puppeteer');
const { spawn } = require('child_process');
const path = require('path');

async function recordAnimation() {
  // Launch browser
  const browser = await puppeteer.launch({
    headless: false,
    args: ['--window-size=1920,1080']
  });
  
  const page = await browser.newPage();
  await page.setViewport({ width: 1920, height: 1080 });
  
  // Navigate to your Flutter app
  await page.goto('http://localhost:5001', { waitUntil: 'networkidle0' });
  
  // Start ffmpeg recording
  const ffmpeg = spawn('ffmpeg', [
    '-y',
    '-f', 'gdigrab',
    '-framerate', '60',
    '-i', 'desktop',
    '-vcodec', 'libx264',
    '-preset', 'ultrafast',
    '-crf', '18',
    'koutu_animation.mp4'
  ]);
  
  // Wait for animation (adjust timing as needed)
  await page.waitForTimeout(8000); // 8 seconds for full animation
  
  // Stop recording
  ffmpeg.stdin.write('q');
  
  await browser.close();
}

recordAnimation();
```

### Setup:
```bash
npm init -y
npm install puppeteer
node record_animation.js
```

## Method 3: Using Flutter Web Screen Recorder Package

Add to `pubspec.yaml`:
```yaml
dependencies:
  flutter_screen_recording: ^1.1.2
```

Then modify your Flutter code:
```dart
import 'package:flutter_screen_recording/flutter_screen_recording.dart';

// In your widget
ElevatedButton(
  onPressed: () async {
    await FlutterScreenRecording.startRecordScreen("koutu_animation");
    // Wait for animation
    await Future.delayed(Duration(seconds: 8));
    await FlutterScreenRecording.stopRecordScreen;
  },
  child: Text('Record Animation'),
)
```

## Method 4: Browser Extension

Use Chrome extensions like:
- **Loom** - Easy recording with automatic uploads
- **Screencastify** - Good quality, saves locally
- **Awesome Screenshot** - Simple and free

## Method 5: PowerShell Script (Windows)

Create `record_flutter.ps1`:
```powershell
# Start Flutter app
Start-Process powershell -ArgumentList "flutter run -d chrome --web-port=5001"

# Wait for app to load
Start-Sleep -Seconds 5

# Use Windows Game Bar (Win+G) or any screen recorder
Write-Host "Press Win+Alt+R to start recording"
Write-Host "Animation will play for ~8 seconds"
Write-Host "Press Win+Alt+R again to stop"

# Keep script running
Read-Host "Press Enter when recording is complete"
```

## Recommended Settings for Best Quality

- **Resolution**: 1920x1080 or 1280x720
- **Frame Rate**: 60 FPS (smooth animation)
- **Format**: MP4 (H.264 codec)
- **Bitrate**: 5000-8000 kbps
- **Audio**: Not needed (mute)

## Quick Solution

The easiest immediate solution:
1. Open your Flutter app in Chrome
2. Press F11 for fullscreen
3. Use Windows Game Bar: `Win + Alt + R` to start/stop recording
4. Find video in: `Videos\Captures` folder

The video will show the complete animation sequence:
- Loading screen
- Wardrobe doors opening
- Golden light effect
- Clothes revealing
- KOUTU logo with lightning effect