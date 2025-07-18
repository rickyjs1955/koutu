import 'package:flutter/material.dart';
import 'package:flutter/scheduler.dart';
import 'dart:async';
import 'dart:developer' as developer;
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';

/// Performance monitoring widget for development
class PerformanceMonitor extends StatefulWidget {
  final Widget child;
  final bool enabled;
  final bool showOverlay;
  
  const PerformanceMonitor({
    super.key,
    required this.child,
    this.enabled = true,
    this.showOverlay = true,
  });

  @override
  State<PerformanceMonitor> createState() => _PerformanceMonitorState();
}

class _PerformanceMonitorState extends State<PerformanceMonitor> 
    with WidgetsBindingObserver {
  // Performance metrics
  double _fps = 60.0;
  double _frameTime = 0.0;
  double _cpuUsage = 0.0;
  double _memoryUsage = 0.0;
  int _widgetCount = 0;
  int _renderObjectCount = 0;
  
  // Frame tracking
  int _frameCount = 0;
  DateTime _lastFrameTime = DateTime.now();
  final List<double> _frameTimes = [];
  
  // Memory tracking
  Timer? _metricsTimer;
  final _stopwatch = Stopwatch();
  
  @override
  void initState() {
    super.initState();
    if (widget.enabled) {
      WidgetsBinding.instance.addObserver(this);
      WidgetsBinding.instance.addPostFrameCallback((_) => _startMonitoring());
    }
  }
  
  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _metricsTimer?.cancel();
    super.dispose();
  }
  
  void _startMonitoring() {
    // Track frame rate
    SchedulerBinding.instance.addPersistentFrameCallback(_onFrame);
    
    // Update metrics periodically
    _metricsTimer = Timer.periodic(const Duration(seconds: 1), (_) {
      _updateMetrics();
    });
  }
  
  void _onFrame(Duration timestamp) {
    if (!widget.enabled) return;
    
    _frameCount++;
    
    final now = DateTime.now();
    final elapsed = now.difference(_lastFrameTime);
    
    if (elapsed.inMilliseconds > 16) {
      // Frame took longer than 16ms (60 FPS)
      _frameTimes.add(elapsed.inMilliseconds.toDouble());
    }
    
    if (elapsed >= const Duration(seconds: 1)) {
      setState(() {
        _fps = (_frameCount / elapsed.inSeconds).clamp(0, 60);
        _frameTime = _frameTimes.isEmpty 
            ? 0 
            : _frameTimes.reduce((a, b) => a + b) / _frameTimes.length;
        _frameCount = 0;
        _lastFrameTime = now;
        _frameTimes.clear();
      });
    }
  }
  
  void _updateMetrics() {
    if (!mounted) return;
    
    // Count widgets and render objects
    int widgetCount = 0;
    int renderObjectCount = 0;
    
    void countWidgets(Element element) {
      widgetCount++;
      if (element.renderObject != null) {
        renderObjectCount++;
      }
      element.visitChildren(countWidgets);
    }
    
    context.visitChildElements(countWidgets);
    
    setState(() {
      _widgetCount = widgetCount;
      _renderObjectCount = renderObjectCount;
      
      // Estimate memory usage (this is a rough approximation)
      _memoryUsage = (_widgetCount * 0.5 + _renderObjectCount * 2.0).clamp(0, 100);
      
      // Estimate CPU usage based on frame time
      _cpuUsage = (_frameTime / 16.0 * 100).clamp(0, 100);
    });
    
    // Log performance issues
    if (_fps < 30) {
      developer.log(
        'Low FPS detected: $_fps',
        name: 'PerformanceMonitor',
        level: 900, // Warning level
      );
    }
    
    if (_memoryUsage > 80) {
      developer.log(
        'High memory usage: $_memoryUsage%',
        name: 'PerformanceMonitor',
        level: 900,
      );
    }
  }
  
  @override
  Widget build(BuildContext context) {
    return Stack(
      children: [
        widget.child,
        if (widget.enabled && widget.showOverlay)
          Positioned(
            top: MediaQuery.of(context).padding.top,
            right: 0,
            child: _buildOverlay(),
          ),
      ],
    );
  }
  
  Widget _buildOverlay() {
    return Container(
      padding: const EdgeInsets.all(8),
      margin: const EdgeInsets.all(8),
      decoration: BoxDecoration(
        color: Colors.black87,
        borderRadius: BorderRadius.circular(8),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: [
          _buildMetric('FPS', _fps.toStringAsFixed(1), _getFPSColor()),
          _buildMetric('Frame', '${_frameTime.toStringAsFixed(1)}ms', _getFrameTimeColor()),
          _buildMetric('CPU', '${_cpuUsage.toStringAsFixed(0)}%', _getCPUColor()),
          _buildMetric('Memory', '${_memoryUsage.toStringAsFixed(0)}%', _getMemoryColor()),
          const Divider(color: Colors.white24, height: 8),
          _buildMetric('Widgets', _widgetCount.toString(), Colors.white),
          _buildMetric('Render', _renderObjectCount.toString(), Colors.white),
        ],
      ),
    );
  }
  
  Widget _buildMetric(String label, String value, Color color) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          SizedBox(
            width: 60,
            child: Text(
              label,
              style: const TextStyle(
                color: Colors.white70,
                fontSize: 10,
                fontFamily: 'monospace',
              ),
            ),
          ),
          Text(
            value,
            style: TextStyle(
              color: color,
              fontSize: 10,
              fontWeight: FontWeight.bold,
              fontFamily: 'monospace',
            ),
          ),
        ],
      ),
    );
  }
  
  Color _getFPSColor() {
    if (_fps >= 55) return Colors.green;
    if (_fps >= 30) return Colors.orange;
    return Colors.red;
  }
  
  Color _getFrameTimeColor() {
    if (_frameTime <= 16) return Colors.green;
    if (_frameTime <= 33) return Colors.orange;
    return Colors.red;
  }
  
  Color _getCPUColor() {
    if (_cpuUsage <= 50) return Colors.green;
    if (_cpuUsage <= 80) return Colors.orange;
    return Colors.red;
  }
  
  Color _getMemoryColor() {
    if (_memoryUsage <= 50) return Colors.green;
    if (_memoryUsage <= 80) return Colors.orange;
    return Colors.red;
  }
}

/// Widget build tracker for debugging
class WidgetBuildTracker extends StatelessWidget {
  final Widget child;
  final String name;
  final bool logBuilds;
  
  const WidgetBuildTracker({
    super.key,
    required this.child,
    required this.name,
    this.logBuilds = true,
  });

  @override
  Widget build(BuildContext context) {
    if (logBuilds) {
      developer.log(
        'Building: $name',
        name: 'WidgetBuildTracker',
        level: 500, // Fine level
      );
    }
    
    return child;
  }
}

/// Memory profiler widget
class MemoryProfiler extends StatefulWidget {
  final Widget child;
  final Duration updateInterval;
  final void Function(MemoryInfo)? onMemoryUpdate;
  
  const MemoryProfiler({
    super.key,
    required this.child,
    this.updateInterval = const Duration(seconds: 5),
    this.onMemoryUpdate,
  });

  @override
  State<MemoryProfiler> createState() => _MemoryProfilerState();
}

class _MemoryProfilerState extends State<MemoryProfiler> {
  Timer? _timer;
  MemoryInfo _currentMemoryInfo = const MemoryInfo();
  
  @override
  void initState() {
    super.initState();
    _startProfiling();
  }
  
  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }
  
  void _startProfiling() {
    _timer = Timer.periodic(widget.updateInterval, (_) {
      _profileMemory();
    });
    
    // Initial profile
    _profileMemory();
  }
  
  void _profileMemory() {
    // Count image cache
    int imageCacheCount = 0;
    int imageCacheSize = 0;
    
    PaintingBinding.instance.imageCache.currentSize;
    imageCacheCount = PaintingBinding.instance.imageCache.currentSizeBytes;
    imageCacheSize = PaintingBinding.instance.imageCache.currentSizeBytes;
    
    // Count widgets
    int widgetCount = 0;
    void countWidgets(Element element) {
      widgetCount++;
      element.visitChildren(countWidgets);
    }
    
    if (mounted) {
      context.visitChildElements(countWidgets);
    }
    
    final memoryInfo = MemoryInfo(
      widgetCount: widgetCount,
      imageCacheCount: imageCacheCount,
      imageCacheSize: imageCacheSize,
      timestamp: DateTime.now(),
    );
    
    setState(() {
      _currentMemoryInfo = memoryInfo;
    });
    
    widget.onMemoryUpdate?.call(memoryInfo);
    
    // Log if memory usage is high
    if (imageCacheSize > 100 * 1024 * 1024) { // 100MB
      developer.log(
        'High image cache usage: ${(imageCacheSize / 1024 / 1024).toStringAsFixed(1)}MB',
        name: 'MemoryProfiler',
        level: 900,
      );
    }
  }
  
  @override
  Widget build(BuildContext context) {
    return widget.child;
  }
}

class MemoryInfo {
  final int widgetCount;
  final int imageCacheCount;
  final int imageCacheSize;
  final DateTime timestamp;
  
  const MemoryInfo({
    this.widgetCount = 0,
    this.imageCacheCount = 0,
    this.imageCacheSize = 0,
    DateTime? timestamp,
  }) : timestamp = timestamp ?? const DateTime(0);
  
  String get formattedImageCacheSize {
    if (imageCacheSize < 1024) return '${imageCacheSize}B';
    if (imageCacheSize < 1024 * 1024) {
      return '${(imageCacheSize / 1024).toStringAsFixed(1)}KB';
    }
    return '${(imageCacheSize / 1024 / 1024).toStringAsFixed(1)}MB';
  }
}