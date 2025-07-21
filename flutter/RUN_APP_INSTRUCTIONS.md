# How to Run the Koutu Fashion AI Flutter App

Since there's a line ending issue in the WSL environment, please run the app manually using these steps:

## Option 1: Using Command Prompt or PowerShell (Recommended)

1. Open Command Prompt or PowerShell on Windows
2. Navigate to the Flutter project:
   ```
   cd C:\Users\monmo\koutu\flutter
   ```

3. Install dependencies:
   ```
   flutter pub get
   ```

4. Run the app in Chrome:
   ```
   flutter run -d chrome --web-port=5000
   ```

5. The app will automatically open in Chrome at: **http://localhost:5000**

## Option 2: Using the Demo Script

1. Open PowerShell
2. Navigate to the Flutter project:
   ```
   cd C:\Users\monmo\koutu\flutter
   ```

3. Run the demo script:
   ```
   .\run_demo_windows.ps1
   ```

## Features You'll See:

1. **Home Screen**: AI-powered dashboard with quick actions
2. **Capture Garment**: Upload images and draw polygons around garments
3. **Digital Wardrobe**: View and manage your garment collection
4. **AI Outfit Builder**: Get AI-powered outfit suggestions
5. **Analytics**: Track your fashion habits

## Troubleshooting:

- If Flutter is not recognized, ensure it's in your PATH
- If dependencies fail, run `flutter doctor` to check your setup
- For web-specific issues, run `flutter doctor -v`

## Navigation:

Once the app is running, you can navigate through:
- Click "Capture Garment" to upload and tag clothes
- Click "My Wardrobe" to view your digital collection
- Click "AI Outfit Builder" for personalized suggestions
- Click "Analytics" to see fashion insights

The app will be available at: **http://localhost:5000**