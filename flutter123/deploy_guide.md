# KOUTU Deployment Guide

## Quick Local Testing on Phone

1. Build the app:
   ```
   .\build_full_animation.bat
   ```

2. Start the mobile server:
   ```
   .\serve_mobile.bat
   ```

3. Find your computer's IP address from the output (e.g., 192.168.1.100)

4. On your phone:
   - Connect to the same WiFi network as your computer
   - Open your browser
   - Go to: `http://[YOUR-IP]:8888`

## Deploy to GitHub Pages (Free Hosting)

1. Create a new repository on GitHub named `koutu-web`

2. Build and prepare files:
   ```
   .\build_full_animation.bat
   ```

3. Copy the `build\web` folder contents to your new repository

4. Enable GitHub Pages:
   - Go to repository Settings
   - Scroll to "Pages" section
   - Source: Deploy from a branch
   - Branch: main
   - Folder: / (root)
   - Save

5. Your app will be available at:
   `https://[your-username].github.io/koutu-web/`

## Deploy to Netlify (Free Hosting)

1. Build the app:
   ```
   .\build_full_animation.bat
   ```

2. Go to https://www.netlify.com/

3. Drag and drop your `build\web` folder to deploy

4. You'll get an instant URL like:
   `https://amazing-koutu-123456.netlify.app`

## Deploy to Firebase Hosting

1. Install Firebase CLI:
   ```
   npm install -g firebase-tools
   ```

2. Initialize Firebase:
   ```
   firebase init hosting
   ```

3. Build and deploy:
   ```
   .\build_full_animation.bat
   firebase deploy
   ```

## Important for Mobile Access

Make sure your `build\web\index.html` uses the mobile-optimized version:
```
.\apply_full_animation.bat
.\build_full_animation.bat
```

This ensures:
- Proper mobile viewport settings
- Touch-friendly interactions
- Optimized performance
- Smooth animations