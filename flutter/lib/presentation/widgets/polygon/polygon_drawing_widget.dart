import 'package:flutter/material.dart';
import 'package:flutter/gestures.dart';
import 'polygon_painter.dart';

class PolygonDrawingWidget extends StatefulWidget {
  final Size imageSize;
  final Function(List<Offset>) onPolygonComplete;
  final List<Offset>? initialPoints;
  final Color polygonColor;
  
  const PolygonDrawingWidget({
    Key? key,
    required this.imageSize,
    required this.onPolygonComplete,
    this.initialPoints,
    this.polygonColor = Colors.blue,
  }) : super(key: key);

  @override
  State<PolygonDrawingWidget> createState() => _PolygonDrawingWidgetState();
}

class _PolygonDrawingWidgetState extends State<PolygonDrawingWidget> {
  List<Offset> _points = [];
  bool _isComplete = false;
  int? _activeHandleIndex;
  Offset? _mousePosition;
  bool _isDrawingMode = true;

  @override
  void initState() {
    super.initState();
    if (widget.initialPoints != null) {
      _points = List.from(widget.initialPoints!);
      _isComplete = _points.length > 2;
      _isDrawingMode = false;
    }
  }

  void _addPoint(Offset point) {
    if (_isComplete) return;

    setState(() {
      // Check if clicking near the first point to close polygon
      if (_points.length > 2) {
        final firstPoint = _points.first;
        final distance = (point - firstPoint).distance;
        if (distance < 20) {
          _completePolygon();
          return;
        }
      }
      
      _points.add(point);
    });
  }

  void _completePolygon() {
    if (_points.length < 3) return;
    
    setState(() {
      _isComplete = true;
      _isDrawingMode = false;
    });
    
    widget.onPolygonComplete(_points);
  }

  int? _getHandleIndexAt(Offset position) {
    for (int i = 0; i < _points.length; i++) {
      if ((position - _points[i]).distance < 15) {
        return i;
      }
    }
    return null;
  }

  void _updateHandlePosition(int index, Offset newPosition) {
    setState(() {
      _points[index] = newPosition;
    });
    
    if (_isComplete) {
      widget.onPolygonComplete(_points);
    }
  }

  void _deletePoint(int index) {
    if (_points.length <= 3) return; // Minimum 3 points for a polygon
    
    setState(() {
      _points.removeAt(index);
    });
    
    widget.onPolygonComplete(_points);
  }

  void _reset() {
    setState(() {
      _points.clear();
      _isComplete = false;
      _isDrawingMode = true;
      _activeHandleIndex = null;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Stack(
      children: [
        MouseRegion(
          onHover: (event) {
            setState(() {
              _mousePosition = event.localPosition;
            });
          },
          child: GestureDetector(
            onTapDown: (details) {
              if (_isDrawingMode) {
                _addPoint(details.localPosition);
              } else {
                final handleIndex = _getHandleIndexAt(details.localPosition);
                if (handleIndex != null) {
                  setState(() {
                    _activeHandleIndex = handleIndex;
                  });
                }
              }
            },
            onPanUpdate: (details) {
              if (_activeHandleIndex != null) {
                _updateHandlePosition(_activeHandleIndex!, details.localPosition);
              }
            },
            onPanEnd: (details) {
              setState(() {
                _activeHandleIndex = null;
              });
            },
            child: CustomPaint(
              size: widget.imageSize,
              painter: PolygonPainter(
                points: _points,
                isComplete: _isComplete,
                strokeColor: widget.polygonColor,
                fillColor: widget.polygonColor,
                activeHandleIndex: _activeHandleIndex,
              ),
            ),
          ),
        ),
        
        // Drawing instructions
        if (_isDrawingMode && _points.isEmpty)
          Positioned(
            top: 20,
            left: 20,
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
              decoration: BoxDecoration(
                color: Colors.black87,
                borderRadius: BorderRadius.circular(20),
              ),
              child: const Text(
                'Click to add points. Click near first point to close.',
                style: TextStyle(color: Colors.white, fontSize: 14),
              ),
            ),
          ),
        
        // Control buttons
        Positioned(
          bottom: 20,
          right: 20,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              if (!_isComplete && _points.length > 2)
                FloatingActionButton.small(
                  onPressed: _completePolygon,
                  backgroundColor: Colors.green,
                  child: const Icon(Icons.check),
                  tooltip: 'Complete polygon',
                ),
              const SizedBox(height: 8),
              if (_points.isNotEmpty)
                FloatingActionButton.small(
                  onPressed: _reset,
                  backgroundColor: Colors.red,
                  child: const Icon(Icons.refresh),
                  tooltip: 'Reset',
                ),
              const SizedBox(height: 8),
              if (_isComplete)
                FloatingActionButton.small(
                  onPressed: () {
                    setState(() {
                      _isDrawingMode = !_isDrawingMode;
                    });
                  },
                  backgroundColor: _isDrawingMode ? Colors.blue : Colors.orange,
                  child: Icon(_isDrawingMode ? Icons.draw : Icons.pan_tool),
                  tooltip: _isDrawingMode ? 'Switch to edit mode' : 'Switch to draw mode',
                ),
            ],
          ),
        ),
      ],
    );
  }
}