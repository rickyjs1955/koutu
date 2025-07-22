import 'dart:ui' as ui;
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'dart:typed_data';
import 'dart:convert';
import 'dart:html' as html;
import 'dart:async';

class AnimationRecorder extends StatefulWidget {
  final Widget child;
  final Duration duration;
  final int fps;
  
  const AnimationRecorder({
    Key? key,
    required this.child,
    required this.duration,
    this.fps = 30,
  }) : super(key: key);

  @override
  State<AnimationRecorder> createState() => _AnimationRecorderState();
}

class _AnimationRecorderState extends State<AnimationRecorder> with TickerProviderStateMixin {
  final GlobalKey _repaintKey = GlobalKey();
  late AnimationController _controller;
  final List<String> _frames = [];
  bool _isRecording = false;
  bool _isExporting = false;
  double _recordingProgress = 0.0;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      duration: widget.duration,
      vsync: this,
    );
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  Future<void> _startRecording() async {
    setState(() {
      _isRecording = true;
      _frames.clear();
      _recordingProgress = 0.0;
    });

    // Calculate frame interval
    final frameInterval = Duration(milliseconds: (1000 / widget.fps).round());
    final totalFrames = (widget.duration.inMilliseconds / frameInterval.inMilliseconds).round();

    // Start animation
    _controller.forward(from: 0.0);

    // Capture frames
    for (int i = 0; i < totalFrames; i++) {
      await _captureFrame();
      setState(() {
        _recordingProgress = (i + 1) / totalFrames;
      });
      await Future.delayed(frameInterval);
    }

    setState(() {
      _isRecording = false;
    });

    // Export as GIF or individual frames
    _exportFrames();
  }

  Future<void> _captureFrame() async {
    try {
      RenderRepaintBoundary boundary = _repaintKey.currentContext!
          .findRenderObject() as RenderRepaintBoundary;
      
      ui.Image image = await boundary.toImage(pixelRatio: 2.0);
      ByteData? byteData = await image.toByteData(format: ui.ImageByteFormat.png);
      
      if (byteData != null) {
        final base64 = base64Encode(byteData.buffer.asUint8List());
        _frames.add('data:image/png;base64,$base64');
      }
    } catch (e) {
      print('Error capturing frame: $e');
    }
  }

  void _exportFrames() {
    setState(() {
      _isExporting = true;
    });

    // Create a simple HTML page with all frames
    final html.StringBuffer htmlContent = html.StringBuffer();
    htmlContent.write('''
<!DOCTYPE html>
<html>
<head>
  <title>Koutu Animation Frames</title>
  <style>
    body { 
      font-family: Arial, sans-serif; 
      padding: 20px;
      background: #f0f0f0;
    }
    .controls {
      margin-bottom: 20px;
      padding: 20px;
      background: white;
      border-radius: 8px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .frame-container {
      background: white;
      padding: 20px;
      border-radius: 8px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    #animation {
      width: 100%;
      max-width: 800px;
      margin: 0 auto;
      display: block;
    }
    button {
      padding: 10px 20px;
      margin: 5px;
      border: none;
      border-radius: 4px;
      background: #2196F3;
      color: white;
      cursor: pointer;
      font-size: 16px;
    }
    button:hover {
      background: #1976D2;
    }
    .info {
      margin-top: 10px;
      color: #666;
    }
  </style>
</head>
<body>
  <h1>Koutu Animation Export</h1>
  <div class="controls">
    <button onclick="playAnimation()">Play Animation</button>
    <button onclick="downloadFrames()">Download All Frames (ZIP)</button>
    <button onclick="createGif()">Create GIF (External Tool Required)</button>
    <div class="info">
      <p>Total Frames: ${_frames.length}</p>
      <p>FPS: ${widget.fps}</p>
      <p>Duration: ${widget.duration.inSeconds} seconds</p>
    </div>
  </div>
  <div class="frame-container">
    <img id="animation" src="${_frames.isNotEmpty ? _frames[0] : ''}" />
  </div>
  
  <script>
    const frames = [
      ${_frames.map((frame) => "'$frame'").join(',\n      ')}
    ];
    
    let currentFrame = 0;
    let animationInterval;
    
    function playAnimation() {
      currentFrame = 0;
      clearInterval(animationInterval);
      animationInterval = setInterval(() => {
        document.getElementById('animation').src = frames[currentFrame];
        currentFrame = (currentFrame + 1) % frames.length;
      }, ${1000 / widget.fps});
    }
    
    function downloadFrames() {
      frames.forEach((frame, index) => {
        const link = document.createElement('a');
        link.download = 'frame_' + String(index).padStart(4, '0') + '.png';
        link.href = frame;
        link.click();
      });
    }
    
    function createGif() {
      alert('To create a GIF or MP4:\\n\\n1. Download all frames\\n2. Use online tools like:\\n   - ezgif.com (GIF)\\n   - video.online-convert.com (MP4)\\n   - Adobe Express (GIF/MP4)\\n\\n3. Or use FFmpeg:\\n   ffmpeg -framerate ${widget.fps} -i frame_%04d.png -c:v libx264 koutu_animation.mp4');
    }
    
    // Auto-play on load
    playAnimation();
  </script>
</body>
</html>
    ''');

    // Download HTML file
    final blob = html.Blob([htmlContent.toString()]);
    final url = html.Url.createObjectUrlFromBlob(blob);
    final anchor = html.document.createElement('a') as html.AnchorElement
      ..href = url
      ..download = 'koutu_animation.html';
    html.document.body!.append(anchor);
    anchor.click();
    anchor.remove();
    html.Url.revokeObjectUrl(url);

    setState(() {
      _isExporting = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Stack(
      children: [
        RepaintBoundary(
          key: _repaintKey,
          child: widget.child,
        ),
        Positioned(
          top: 20,
          right: 20,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              if (!_isRecording && !_isExporting)
                ElevatedButton.icon(
                  onPressed: _startRecording,
                  icon: const Icon(Icons.fiber_manual_record, color: Colors.red),
                  label: const Text('Record Animation'),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: Colors.white,
                    foregroundColor: Colors.black87,
                  ),
                ),
              if (_isRecording)
                Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: Colors.white,
                    borderRadius: BorderRadius.circular(8),
                    boxShadow: [
                      BoxShadow(
                        color: Colors.black.withOpacity(0.1),
                        blurRadius: 4,
                        offset: const Offset(0, 2),
                      ),
                    ],
                  ),
                  child: Column(
                    children: [
                      const Text('Recording...'),
                      const SizedBox(height: 8),
                      SizedBox(
                        width: 200,
                        child: LinearProgressIndicator(
                          value: _recordingProgress,
                          backgroundColor: Colors.grey[300],
                          valueColor: const AlwaysStoppedAnimation<Color>(Colors.red),
                        ),
                      ),
                      const SizedBox(height: 4),
                      Text('${(_recordingProgress * 100).toInt()}%'),
                    ],
                  ),
                ),
              if (_isExporting)
                Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: Colors.white,
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: const Row(
                    children: [
                      CircularProgressIndicator(strokeWidth: 2),
                      SizedBox(width: 8),
                      Text('Exporting...'),
                    ],
                  ),
                ),
            ],
          ),
        ),
      ],
    );
  }
}