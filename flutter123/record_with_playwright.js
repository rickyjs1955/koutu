// record_with_playwright.js
// This script uses Playwright to capture screenshots and create a video

const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

async function captureAnimation() {
  console.log('Starting animation capture...');
  
  // Create screenshots directory
  const screenshotsDir = './animation_frames';
  if (!fs.existsSync(screenshotsDir)) {
    fs.mkdirSync(screenshotsDir);
  }

  // Launch browser
  const browser = await chromium.launch({
    headless: false, // Set to true for background recording
    args: ['--window-size=1280,720']
  });

  const context = await browser.newContext({
    viewport: { width: 1280, height: 720 },
    deviceScaleFactor: 2, // Higher quality
  });

  const page = await context.newPage();

  console.log('Navigating to Flutter app...');
  await page.goto('http://localhost:5001', { waitUntil: 'networkidle' });

  // Wait for loading to complete
  await page.waitForTimeout(1000);

  console.log('Capturing animation frames...');
  
  // Capture frames at 30 FPS for 8 seconds
  const fps = 30;
  const duration = 8; // seconds
  const totalFrames = fps * duration;

  for (let i = 0; i < totalFrames; i++) {
    await page.screenshot({
      path: path.join(screenshotsDir, `frame_${String(i).padStart(4, '0')}.png`),
      type: 'png'
    });
    await page.waitForTimeout(1000 / fps); // Wait for next frame
    
    if (i % 30 === 0) {
      console.log(`Captured ${i}/${totalFrames} frames...`);
    }
  }

  await browser.close();
  console.log('Frame capture complete!');

  // Convert frames to video using FFmpeg
  console.log('Converting frames to video...');
  
  const ffmpegCommand = `ffmpeg -y -framerate ${fps} -i ${screenshotsDir}/frame_%04d.png -c:v libx264 -preset slow -crf 18 -pix_fmt yuv420p koutu_animation.mp4`;
  
  try {
    await execPromise(ffmpegCommand);
    console.log('Video created successfully: koutu_animation.mp4');
    
    // Clean up frames
    console.log('Cleaning up frames...');
    const files = fs.readdirSync(screenshotsDir);
    files.forEach(file => {
      if (file.endsWith('.png')) {
        fs.unlinkSync(path.join(screenshotsDir, file));
      }
    });
    fs.rmdirSync(screenshotsDir);
    
  } catch (error) {
    console.error('Error creating video:', error);
    console.log('Make sure FFmpeg is installed: https://ffmpeg.org/download.html');
  }
}

// Run the capture
captureAnimation().catch(console.error);