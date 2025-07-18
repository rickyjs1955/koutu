import 'dart:io';
import 'dart:typed_data';
import 'dart:ui' as ui;
import 'package:flutter/material.dart';
import 'package:injectable/injectable.dart';
import 'package:koutu/core/utils/logger.dart';

@lazySingleton
class ColorExtractionService {
  /// Extract color palette from image
  Future<ColorExtractionResult> extractColors(
    File imageFile, {
    int colorCount = 5,
  }) async {
    try {
      Logger.info('Extracting colors from image: ${imageFile.path}');

      final bytes = await imageFile.readAsBytes();
      final codec = await ui.instantiateImageCodec(bytes);
      final frame = await codec.getNextFrame();
      final image = frame.image;

      // Get image data
      final byteData = await image.toByteData(format: ui.ImageByteFormat.rawRgba);
      if (byteData == null) {
        throw Exception('Failed to get image byte data');
      }

      // Extract colors using k-means clustering
      final colors = await _extractColorsFromBytes(
        byteData.buffer.asUint8List(),
        image.width,
        image.height,
        colorCount,
      );

      // Convert to hex strings
      final hexColors = colors.map(_colorToHex).toList();
      final dominantColor = hexColors.first;

      Logger.info('Extracted ${hexColors.length} colors, dominant: $dominantColor');

      return ColorExtractionResult(
        palette: hexColors,
        dominantColor: dominantColor,
      );
    } catch (e) {
      Logger.error('Color extraction failed', error: e);
      rethrow;
    }
  }

  /// Extract colors using k-means clustering
  Future<List<Color>> _extractColorsFromBytes(
    Uint8List bytes,
    int width,
    int height,
    int colorCount,
  ) async {
    // Sample pixels (for performance, we don't analyze every pixel)
    final sampleSize = 5000;
    final pixelCount = width * height;
    final step = (pixelCount / sampleSize).ceil();
    
    final sampledColors = <Color>[];
    
    for (int i = 0; i < pixelCount; i += step) {
      final offset = i * 4; // RGBA
      if (offset + 3 < bytes.length) {
        final r = bytes[offset];
        final g = bytes[offset + 1];
        final b = bytes[offset + 2];
        final a = bytes[offset + 3];
        
        // Only consider non-transparent pixels
        if (a > 128) {
          sampledColors.add(Color.fromARGB(255, r, g, b));
        }
      }
    }

    if (sampledColors.isEmpty) {
      return [Colors.grey];
    }

    // Perform k-means clustering
    return _kMeansClustering(sampledColors, colorCount);
  }

  /// K-means clustering algorithm
  List<Color> _kMeansClustering(List<Color> colors, int k) {
    if (colors.length <= k) {
      return colors;
    }

    // Initialize centroids with random colors
    final centroids = <Color>[];
    final usedIndices = <int>{};
    
    while (centroids.length < k && usedIndices.length < colors.length) {
      final index = DateTime.now().millisecondsSinceEpoch % colors.length;
      if (!usedIndices.contains(index)) {
        centroids.add(colors[index]);
        usedIndices.add(index);
      }
    }

    // Iterate until convergence
    const maxIterations = 20;
    for (int iteration = 0; iteration < maxIterations; iteration++) {
      // Assign colors to nearest centroid
      final clusters = List.generate(k, (_) => <Color>[]);
      
      for (final color in colors) {
        int nearestIndex = 0;
        double minDistance = double.infinity;
        
        for (int i = 0; i < centroids.length; i++) {
          final distance = _colorDistance(color, centroids[i]);
          if (distance < minDistance) {
            minDistance = distance;
            nearestIndex = i;
          }
        }
        
        clusters[nearestIndex].add(color);
      }

      // Update centroids
      bool changed = false;
      for (int i = 0; i < k; i++) {
        if (clusters[i].isNotEmpty) {
          final newCentroid = _averageColor(clusters[i]);
          if (newCentroid != centroids[i]) {
            centroids[i] = newCentroid;
            changed = true;
          }
        }
      }

      // Check for convergence
      if (!changed) {
        break;
      }
    }

    // Sort by luminance (brightest to darkest)
    centroids.sort((a, b) {
      final luminanceA = a.computeLuminance();
      final luminanceB = b.computeLuminance();
      return luminanceB.compareTo(luminanceA);
    });

    return centroids;
  }

  /// Calculate distance between two colors
  double _colorDistance(Color a, Color b) {
    final dr = a.red - b.red;
    final dg = a.green - b.green;
    final db = a.blue - b.blue;
    return dr * dr + dg * dg + db * db;
  }

  /// Calculate average color from a list
  Color _averageColor(List<Color> colors) {
    if (colors.isEmpty) return Colors.grey;

    int r = 0, g = 0, b = 0;
    for (final color in colors) {
      r += color.red;
      g += color.green;
      b += color.blue;
    }

    return Color.fromARGB(
      255,
      (r / colors.length).round(),
      (g / colors.length).round(),
      (b / colors.length).round(),
    );
  }

  /// Convert Color to hex string
  String _colorToHex(Color color) {
    return '#${color.value.toRadixString(16).substring(2).toUpperCase()}';
  }

  /// Get color name from hex
  String getColorName(String hexColor) {
    final color = _hexToColor(hexColor);
    final hue = HSVColor.fromColor(color).hue;
    final saturation = HSVColor.fromColor(color).saturation;
    final value = HSVColor.fromColor(color).value;

    // Check for grayscale
    if (saturation < 0.1) {
      if (value < 0.3) return 'Black';
      if (value < 0.7) return 'Gray';
      return 'White';
    }

    // Determine color based on hue
    if (hue < 10 || hue >= 350) return 'Red';
    if (hue < 30) return 'Orange';
    if (hue < 70) return 'Yellow';
    if (hue < 150) return 'Green';
    if (hue < 200) return 'Cyan';
    if (hue < 260) return 'Blue';
    if (hue < 290) return 'Purple';
    if (hue < 350) return 'Pink';
    
    return 'Unknown';
  }

  /// Convert hex string to Color
  Color _hexToColor(String hex) {
    final buffer = StringBuffer();
    if (hex.length == 6 || hex.length == 7) buffer.write('ff');
    buffer.write(hex.replaceFirst('#', ''));
    return Color(int.parse(buffer.toString(), radix: 16));
  }
}

class ColorExtractionResult {
  final List<String> palette;
  final String dominantColor;

  ColorExtractionResult({
    required this.palette,
    required this.dominantColor,
  });
}