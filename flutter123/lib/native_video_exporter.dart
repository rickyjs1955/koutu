import 'dart:ui' as ui;
import 'dart:typed_data';
import 'dart:async';
import 'dart:convert';
import 'dart:html' as html;
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';

class NativeVideoExporter extends StatefulWidget {
  final Widget child;
  final Duration animationDuration;
  final VoidCallback? onAnimationComplete;
  
  const NativeVideoExporter({
    Key? key,
    required this.child,
    required this.animationDuration,
    this.onAnimationComplete,
  }) : super(key: key);

  @override
  State<NativeVideoExporter> createState() => _NativeVideoExporterState();
}

class _NativeVideoExporterState extends State<NativeVideoExporter> with TickerProviderStateMixin {
  final GlobalKey _repaintKey = GlobalKey();
  late AnimationController _progressController;
  final List<Uint8List> _frames = [];
  bool _isCapturing = false;
  bool _showPreview = false;
  double _captureProgress = 0.0;
  Timer? _captureTimer;
  int _currentPreviewFrame = 0;
  Timer? _previewTimer;
  
  @override
  void initState() {
    super.initState();
    _progressController = AnimationController(
      duration: widget.animationDuration,
      vsync: this,
    );
  }
  
  @override
  void dispose() {
    _progressController.dispose();
    _captureTimer?.cancel();
    _previewTimer?.cancel();
    super.dispose();
  }
  
  Future<void> _startCapture() async {
    setState(() {
      _isCapturing = true;
      _frames.clear();
      _captureProgress = 0.0;
      _showPreview = false;
    });
    
    // Restart the animation
    widget.onAnimationComplete?.call();
    
    // Wait a moment for animation to restart
    await Future.delayed(const Duration(milliseconds: 100));
    
    const fps = 30;
    final frameInterval = Duration(milliseconds: (1000 / fps).round());
    final totalFrames = (widget.animationDuration.inMilliseconds / frameInterval.inMilliseconds).round();
    
    int frameCount = 0;
    _captureTimer = Timer.periodic(frameInterval, (timer) async {
      if (frameCount >= totalFrames) {
        timer.cancel();
        _finishCapture();
        return;
      }
      
      await _captureFrame();
      frameCount++;
      
      setState(() {
        _captureProgress = frameCount / totalFrames;
      });
    });
  }
  
  Future<void> _captureFrame() async {
    try {
      final RenderRepaintBoundary boundary = 
          _repaintKey.currentContext!.findRenderObject() as RenderRepaintBoundary;
      
      final ui.Image image = await boundary.toImage(pixelRatio: 2.0);
      final ByteData? byteData = await image.toByteData(format: ui.ImageByteFormat.png);
      
      if (byteData != null) {
        _frames.add(byteData.buffer.asUint8List());
      }
    } catch (e) {
      print('Error capturing frame: $e');
    }
  }
  
  void _finishCapture() {
    setState(() {
      _isCapturing = false;
      _showPreview = true;
    });
    
    // Start preview animation
    _currentPreviewFrame = 0;
    _previewTimer = Timer.periodic(const Duration(milliseconds: 33), (timer) {
      setState(() {
        _currentPreviewFrame = (_currentPreviewFrame + 1) % _frames.length;
      });
    });
  }
  
  void _exportAsWebM() {
    // For now, just call the GIF export which provides frame export
    // WebM creation requires external tools due to browser limitations
    _exportAsGif();
  }
  
  void _exportAsGif() {
    // Export frames as animated HTML with instructions
    final StringBuffer htmlContent = StringBuffer();
    
    htmlContent.write('''
<!DOCTYPE html>
<html>
<head>
  <title>Koutu Animation - Export to GIF/MP4</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      max-width: 1200px;
      margin: 0 auto;
      padding: 20px;
      background: #f8f9fa;
    }
    .container {
      background: white;
      border-radius: 12px;
      padding: 30px;
      box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    h1 {
      color: #8B6F47;
      margin-bottom: 10px;
    }
    .subtitle {
      color: #666;
      margin-bottom: 30px;
    }
    .animation-container {
      background: #000;
      border-radius: 8px;
      padding: 20px;
      text-align: center;
      margin: 20px 0;
    }
    #animationFrame {
      max-width: 100%;
      height: auto;
      border-radius: 4px;
    }
    .controls {
      display: flex;
      gap: 10px;
      justify-content: center;
      margin: 20px 0;
    }
    button {
      padding: 12px 24px;
      border: none;
      border-radius: 6px;
      font-size: 16px;
      cursor: pointer;
      transition: all 0.3s;
    }
    .play-btn {
      background: #FFD700;
      color: #333;
    }
    .play-btn:hover {
      background: #FFC700;
      transform: translateY(-1px);
    }
    .export-btn {
      background: #4CAF50;
      color: white;
    }
    .export-btn:hover {
      background: #45a049;
      transform: translateY(-1px);
    }
    .instructions {
      background: #FFF9C4;
      border-radius: 8px;
      padding: 20px;
      margin: 20px 0;
    }
    .instructions h3 {
      margin-top: 0;
      color: #F57C00;
    }
    .step {
      margin: 10px 0;
      padding-left: 20px;
    }
    .code {
      background: #263238;
      color: #AEDE88;
      padding: 15px;
      border-radius: 4px;
      font-family: 'Courier New', monospace;
      margin: 10px 0;
      overflow-x: auto;
    }
    .stats {
      display: flex;
      gap: 20px;
      justify-content: center;
      margin: 20px 0;
      color: #666;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>🚀 Koutu Animation Export</h1>
    <p class="subtitle">Your wardrobe animation is ready for export!</p>
    
    <div class="animation-container">
      <img id="animationFrame" src="" alt="Animation Preview">
    </div>
    
    <div class="controls">
      <button class="play-btn" onclick="toggleAnimation()">▶️ Play Animation</button>
      <button class="export-btn" onclick="downloadAllFrames()">📥 Download Frames</button>
    </div>
    
    <div class="stats">
      <span>📊 Total Frames: ${_frames.length}</span>
      <span>⏱️ Duration: ${widget.animationDuration.inSeconds}s</span>
      <span>🎬 FPS: 30</span>
    </div>
    
    <div class="instructions">
      <h3>🎯 How to Create GIF/MP4</h3>
      
      <div class="step">
        <strong>Option 1: Online Converters (Easiest)</strong>
        <ol>
          <li>Click "Download Frames" above</li>
          <li>Visit <a href="https://ezgif.com/maker" target="_blank">ezgif.com</a> for GIF</li>
          <li>Or visit <a href="https://www.online-convert.com/" target="_blank">online-convert.com</a> for MP4</li>
          <li>Upload all frames and set to 30 FPS</li>
        </ol>
      </div>
      
      <div class="step">
        <strong>Option 2: FFmpeg (Professional)</strong>
        <div class="code">
# For MP4 (recommended)
ffmpeg -framerate 30 -i frame_%04d.png -c:v libx264 -pix_fmt yuv420p koutu_animation.mp4

# For GIF
ffmpeg -framerate 30 -i frame_%04d.png -vf "scale=800:-1" koutu_animation.gif
        </div>
      </div>
      
      <div class="step">
        <strong>Option 3: Adobe Creative Cloud</strong>
        <p>Import frames into Premiere Pro or After Effects for professional editing</p>
      </div>
    </div>
  </div>
  
  <script>
    const frames = [
''');

    // Add frames as base64
    for (int i = 0; i < _frames.length; i++) {
      final base64 = base64Encode(_frames[i]);
      htmlContent.write("      'data:image/png;base64,$base64'");
      if (i < _frames.length - 1) htmlContent.write(',\n');
    }
    
    htmlContent.write('''
    ];
    
    let currentFrame = 0;
    let isPlaying = false;
    let animationInterval;
    
    function toggleAnimation() {
      if (isPlaying) {
        clearInterval(animationInterval);
        isPlaying = false;
        document.querySelector('.play-btn').textContent = '▶️ Play Animation';
      } else {
        isPlaying = true;
        document.querySelector('.play-btn').textContent = '⏸️ Pause';
        animationInterval = setInterval(() => {
          document.getElementById('animationFrame').src = frames[currentFrame];
          currentFrame = (currentFrame + 1) % frames.length;
        }, 33);
      }
    }
    
    function downloadAllFrames() {
      const link = document.createElement('a');
      frames.forEach((frame, index) => {
        setTimeout(() => {
          link.download = 'frame_' + String(index).padStart(4, '0') + '.png';
          link.href = frame;
          link.click();
        }, index * 100);
      });
    }
    
    // Initialize
    document.getElementById('animationFrame').src = frames[0];
    toggleAnimation();
  </script>
</body>
</html>
''');

    // Download HTML file
    final blob = html.Blob([htmlContent.toString()], 'text/html');
    final url = html.Url.createObjectUrlFromBlob(blob);
    final anchor = html.document.createElement('a') as html.AnchorElement
      ..href = url
      ..download = 'koutu_animation_export.html';
    anchor.click();
    html.Url.revokeObjectUrl(url);
  }
  
  @override
  Widget build(BuildContext context) {
    return Stack(
      children: [
        RepaintBoundary(
          key: _repaintKey,
          child: widget.child,
        ),
        
        // Capture controls
        Positioned(
          bottom: 20,
          right: 20,
          child: AnimatedContainer(
            duration: const Duration(milliseconds: 300),
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: Colors.white.withOpacity(0.95),
              borderRadius: BorderRadius.circular(12),
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withOpacity(0.1),
                  blurRadius: 10,
                  offset: const Offset(0, 4),
                ),
              ],
            ),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                if (!_isCapturing && !_showPreview)
                  ElevatedButton.icon(
                    onPressed: _startCapture,
                    icon: const Icon(Icons.videocam),
                    label: const Text('Capture Animation'),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: const Color(0xFFFFD700),
                      foregroundColor: Colors.black87,
                      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
                    ),
                  ),
                
                if (_isCapturing) ...[
                  const Text(
                    'Capturing...',
                    style: TextStyle(fontWeight: FontWeight.bold),
                  ),
                  const SizedBox(height: 8),
                  SizedBox(
                    width: 200,
                    child: LinearProgressIndicator(
                      value: _captureProgress,
                      backgroundColor: Colors.grey[300],
                      valueColor: const AlwaysStoppedAnimation<Color>(Color(0xFFFFD700)),
                    ),
                  ),
                  const SizedBox(height: 4),
                  Text('${(_captureProgress * 100).toInt()}%'),
                ],
                
                if (_showPreview) ...[
                  const Text(
                    'Preview',
                    style: TextStyle(fontWeight: FontWeight.bold),
                  ),
                  const SizedBox(height: 8),
                  Container(
                    width: 200,
                    height: 112,
                    decoration: BoxDecoration(
                      border: Border.all(color: Colors.grey[300]!),
                      borderRadius: BorderRadius.circular(4),
                    ),
                    child: _frames.isNotEmpty
                        ? Image.memory(
                            _frames[_currentPreviewFrame],
                            fit: BoxFit.contain,
                          )
                        : const SizedBox(),
                  ),
                  const SizedBox(height: 12),
                  Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      ElevatedButton.icon(
                        onPressed: _exportAsGif,
                        icon: const Icon(Icons.download, size: 18),
                        label: const Text('Export'),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: Colors.green,
                          foregroundColor: Colors.white,
                          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                        ),
                      ),
                      const SizedBox(width: 8),
                      ElevatedButton.icon(
                        onPressed: () {
                          setState(() {
                            _showPreview = false;
                            _frames.clear();
                          });
                          _previewTimer?.cancel();
                        },
                        icon: const Icon(Icons.close, size: 18),
                        label: const Text('Close'),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: Colors.grey[600],
                          foregroundColor: Colors.white,
                          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                        ),
                      ),
                    ],
                  ),
                ],
              ],
            ),
          ),
        ),
      ],
    );
  }
}