#!/bin/bash

echo "🎬 Creating MP4 from Koutu Animation Frames"
echo "=========================================="
echo ""

# Check if frames directory exists
if [ ! -d "frames" ]; then
    echo "❌ No 'frames' directory found!"
    echo "Please:"
    echo "1. Create a 'frames' directory here"
    echo "2. Download all frames from the HTML export"
    echo "3. Place them in the frames directory"
    echo "4. Run this script again"
    exit 1
fi

# Check if ffmpeg is installed
if ! command -v ffmpeg &> /dev/null; then
    echo "❌ FFmpeg not installed!"
    echo "Please install FFmpeg first:"
    echo "  Ubuntu/Debian: sudo apt-get install ffmpeg"
    echo "  Mac: brew install ffmpeg"
    echo "  Windows: Download from https://ffmpeg.org/download.html"
    exit 1
fi

echo "✅ Creating MP4 video..."
echo ""

# Create high-quality MP4
ffmpeg -framerate 30 -pattern_type glob -i 'frames/frame_*.png' \
    -c:v libx264 -pix_fmt yuv420p -crf 18 \
    -preset slow -movflags +faststart \
    koutu_animation_hq.mp4

# Create web-optimized MP4
ffmpeg -framerate 30 -pattern_type glob -i 'frames/frame_*.png' \
    -c:v libx264 -pix_fmt yuv420p -crf 23 \
    -preset medium -movflags +faststart \
    -vf "scale=1280:-2" \
    koutu_animation_web.mp4

# Create GIF as bonus
ffmpeg -framerate 30 -pattern_type glob -i 'frames/frame_*.png' \
    -vf "scale=800:-1:flags=lanczos,split[s0][s1];[s0]palettegen[p];[s1][p]paletteuse" \
    koutu_animation.gif

echo ""
echo "✅ Done! Created:"
echo "  - koutu_animation_hq.mp4 (High Quality)"
echo "  - koutu_animation_web.mp4 (Web Optimized)"
echo "  - koutu_animation.gif (Bonus GIF)"
echo ""