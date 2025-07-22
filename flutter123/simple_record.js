// simple_record.js
// Simpler approach using Playwright's video recording feature

const { chromium } = require('playwright');

async function recordAnimation() {
  console.log('Starting video recording...');
  
  const browser = await chromium.launch({
    headless: false // Set to false to see the browser
  });

  const context = await browser.newContext({
    viewport: { width: 1280, height: 720 },
    recordVideo: {
      dir: './videos',
      size: { width: 1280, height: 720 }
    }
  });

  const page = await context.newPage();
  
  console.log('Loading Flutter app...');
  await page.goto('http://localhost:5001');
  
  // Wait for initial loading
  await page.waitForTimeout(2000);
  
  console.log('Recording animation (8 seconds)...');
  // Record for 8 seconds to capture full animation
  await page.waitForTimeout(8000);
  
  console.log('Saving video...');
  await context.close();
  await browser.close();
  
  console.log('Video saved in ./videos folder!');
  console.log('Look for a .webm file that you can convert to MP4');
}

recordAnimation().catch(console.error);