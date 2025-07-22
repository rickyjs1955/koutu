# Troubleshooting Phone Access

## Quick Checks

1. **Same WiFi Network?**
   - Make sure both your computer and phone are on the same WiFi network
   - Not on guest network vs main network

2. **Windows Firewall**
   - Windows Firewall might be blocking the connection
   - Try temporarily disabling Windows Firewall:
     ```
     Windows Security → Firewall & network protection → Turn off for Private network
     ```

3. **Try Different Port**
   - Some ports might be blocked
   - Try running on port 3000 or 5000:
     ```
     flutter run -d chrome --web-port=3000 lib/main.dart
     ```

## Solution 1: Windows Firewall Rule

Create a firewall rule to allow Flutter:

1. Open Windows Defender Firewall with Advanced Security
2. Click "Inbound Rules" → "New Rule"
3. Choose "Port" → TCP → Specific local ports: 8085
4. Allow the connection
5. Apply to all profiles
6. Name it "Flutter Web Server"

## Solution 2: Use Python Simple Server

1. First build the web version:
   ```
   flutter build web
   ```

2. Then serve it with Python:
   ```
   cd build\web
   python -m http.server 8000
   ```

3. Access on phone: `http://192.168.1.126:8000`

## Solution 3: Use ngrok (Public URL)

1. Download ngrok from https://ngrok.com
2. Run in a new terminal:
   ```
   ngrok http 8085
   ```
3. Use the public URL it provides on your phone

## Solution 4: Check IP Address

Make sure the IP is correct:
```
ipconfig
```
Look for your WiFi adapter's IPv4 address.

## Solution 5: Direct Connection Test

Test if your phone can reach your computer:
1. On your computer, create a simple test:
   ```
   echo "Hello from PC" > test.html
   python -m http.server 8888
   ```
2. Try accessing `http://192.168.1.126:8888/test.html` on your phone

## Quick Alternative: Use USB

For Android phones:
1. Enable USB debugging
2. Connect via USB
3. Run: `flutter run -d <device-id>`

## Still Not Working?

The animation is working perfectly on desktop. For a quick demo:
1. Record the desktop browser with OBS or screen recorder
2. Or use the MP4 creation scripts you already have
3. Share the video file directly