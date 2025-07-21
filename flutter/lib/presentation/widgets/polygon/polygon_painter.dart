import 'package:flutter/material.dart';
import 'dart:ui' as ui;

class PolygonPainter extends CustomPainter {
  final List<Offset> points;
  final bool isComplete;
  final Color strokeColor;
  final Color fillColor;
  final double strokeWidth;
  final bool showHandles;
  final int? activeHandleIndex;

  PolygonPainter({
    required this.points,
    this.isComplete = false,
    this.strokeColor = Colors.blue,
    this.fillColor = Colors.transparent,
    this.strokeWidth = 2.0,
    this.showHandles = true,
    this.activeHandleIndex,
  });

  @override
  void paint(Canvas canvas, Size size) {
    if (points.isEmpty) return;

    final paint = Paint()
      ..color = strokeColor
      ..strokeWidth = strokeWidth
      ..style = PaintingStyle.stroke
      ..strokeJoin = StrokeJoin.round;

    final fillPaint = Paint()
      ..color = fillColor.withOpacity(0.3)
      ..style = PaintingStyle.fill;

    final path = Path();
    
    // Draw the polygon path
    if (points.isNotEmpty) {
      path.moveTo(points.first.dx, points.first.dy);
      for (int i = 1; i < points.length; i++) {
        path.lineTo(points[i].dx, points[i].dy);
      }
      
      if (isComplete && points.length > 2) {
        path.close();
        // Fill the polygon
        canvas.drawPath(path, fillPaint);
      }
      
      // Draw the stroke
      canvas.drawPath(path, paint);
    }

    // Draw connecting line to mouse position if polygon is not complete
    if (!isComplete && points.length > 0) {
      final dashedPaint = Paint()
        ..color = strokeColor.withOpacity(0.5)
        ..strokeWidth = 1.0
        ..style = PaintingStyle.stroke;
      
      // Draw dashed line effect
      final lastPoint = points.last;
      canvas.drawLine(lastPoint, lastPoint, dashedPaint);
    }

    // Draw handles at vertices
    if (showHandles) {
      final handlePaint = Paint()
        ..color = Colors.white
        ..style = PaintingStyle.fill;
      
      final handleBorderPaint = Paint()
        ..color = strokeColor
        ..strokeWidth = 2.0
        ..style = PaintingStyle.stroke;

      for (int i = 0; i < points.length; i++) {
        final isActive = i == activeHandleIndex;
        final handleRadius = isActive ? 8.0 : 6.0;
        
        // Draw handle shadow
        if (isActive) {
          final shadowPaint = Paint()
            ..color = Colors.black.withOpacity(0.2)
            ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 3);
          canvas.drawCircle(
            Offset(points[i].dx + 1, points[i].dy + 1), 
            handleRadius + 2, 
            shadowPaint
          );
        }
        
        // Draw handle
        canvas.drawCircle(points[i], handleRadius, handlePaint);
        canvas.drawCircle(
          points[i], 
          handleRadius, 
          isActive 
            ? (handleBorderPaint..strokeWidth = 3.0)
            : handleBorderPaint
        );

        // Draw handle number
        if (points.length > 3) {
          final textPainter = TextPainter(
            text: TextSpan(
              text: '${i + 1}',
              style: TextStyle(
                color: strokeColor,
                fontSize: 10,
                fontWeight: FontWeight.bold,
              ),
            ),
            textDirection: TextDirection.ltr,
          );
          textPainter.layout();
          textPainter.paint(
            canvas,
            Offset(
              points[i].dx - textPainter.width / 2,
              points[i].dy - textPainter.height / 2,
            ),
          );
        }
      }
    }
  }

  @override
  bool shouldRepaint(PolygonPainter oldDelegate) {
    return points != oldDelegate.points ||
        isComplete != oldDelegate.isComplete ||
        strokeColor != oldDelegate.strokeColor ||
        fillColor != oldDelegate.fillColor ||
        activeHandleIndex != oldDelegate.activeHandleIndex;
  }
}