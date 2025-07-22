@echo off
echo ========================================
echo  Creating MP4 from Koutu Animation Frames
echo ========================================
echo.

REM Check if frames directory exists
if not exist "frames" (
    echo ERROR: No 'frames' directory found!
    echo Please:
    echo 1. Create a 'frames' directory here
    echo 2. Download all frames from the HTML export
    echo 3. Place them in the frames directory
    echo 4. Run this script again
    pause
    exit /b 1
)

REM Check if ffmpeg is installed
where ffmpeg >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: FFmpeg not installed!
    echo Please download FFmpeg from https://ffmpeg.org/download.html
    echo Add it to your PATH and run this script again
    pause
    exit /b 1
)

echo Creating MP4 video...
echo.

REM Create high-quality MP4
ffmpeg -framerate 30 -i frames\frame_%%04d.png ^
    -c:v libx264 -pix_fmt yuv420p -crf 18 ^
    -preset slow -movflags +faststart ^
    koutu_animation_hq.mp4

REM Create web-optimized MP4
ffmpeg -framerate 30 -i frames\frame_%%04d.png ^
    -c:v libx264 -pix_fmt yuv420p -crf 23 ^
    -preset medium -movflags +faststart ^
    -vf "scale=1280:-2" ^
    koutu_animation_web.mp4

REM Create GIF as bonus
ffmpeg -framerate 30 -i frames\frame_%%04d.png ^
    -vf "scale=800:-1:flags=lanczos,split[s0][s1];[s0]palettegen[p];[s1][p]paletteuse" ^
    koutu_animation.gif

echo.
echo Done! Created:
echo   - koutu_animation_hq.mp4 (High Quality)
echo   - koutu_animation_web.mp4 (Web Optimized)
echo   - koutu_animation.gif (Bonus GIF)
echo.
pause