import 'dart:typed_data';
import 'dart:ui' as ui;
import 'package:flutter/material.dart';
import 'package:image/image.dart' as img;
import 'package:http/http.dart' as http;

/// Service for color palette extraction and color matching
class ColorPaletteService {
  static const int _defaultPaletteSize = 5;
  static const int _maxImageSize = 400;
  
  /// Predefined color names and their RGB values
  static final Map<String, Color> _colorMap = {
    // Basic colors
    'black': const Color(0xFF000000),
    'white': const Color(0xFFFFFFFF),
    'red': const Color(0xFFFF0000),
    'green': const Color(0xFF00FF00),
    'blue': const Color(0xFF0000FF),
    'yellow': const Color(0xFFFFFF00),
    'orange': const Color(0xFFFF8000),
    'purple': const Color(0xFF800080),
    'pink': const Color(0xFFFF69B4),
    'brown': const Color(0xFF8B4513),
    'grey': const Color(0xFF808080),
    'gray': const Color(0xFF808080),
    
    // Extended colors
    'navy': const Color(0xFF000080),
    'maroon': const Color(0xFF800000),
    'teal': const Color(0xFF008080),
    'olive': const Color(0xFF808000),
    'lime': const Color(0xFF00FF00),
    'aqua': const Color(0xFF00FFFF),
    'fuchsia': const Color(0xFFFF00FF),
    'silver': const Color(0xFFC0C0C0),
    'gold': const Color(0xFFFFD700),
    'beige': const Color(0xFFF5F5DC),
    'tan': const Color(0xFFD2B48C),
    'cream': const Color(0xFFFFFDD0),
    'ivory': const Color(0xFFFFFFF0),
    'khaki': const Color(0xFFF0E68C),
    'lavender': const Color(0xFFE6E6FA),
    'mint': const Color(0xFF98FB98),
    'coral': const Color(0xFFFF7F50),
    'salmon': const Color(0xFFFA8072),
    'crimson': const Color(0xFFDC143C),
    'magenta': const Color(0xFFFF00FF),
    'cyan': const Color(0xFF00FFFF),
    'turquoise': const Color(0xFF40E0D0),
    'indigo': const Color(0xFF4B0082),
    'violet': const Color(0xFFEE82EE),
    'plum': const Color(0xFFDDA0DD),
    'rose': const Color(0xFFFF66CC),
    'burgundy': const Color(0xFF800020),
    'emerald': const Color(0xFF50C878),
    'sapphire': const Color(0xFF0F52BA),
    'ruby': const Color(0xFFE0115F),
    'amber': const Color(0xFFFFBF00),
    'charcoal': const Color(0xFF36454F),
    'slate': const Color(0xFF708090),
    'pearl': const Color(0xFFF0EAD6),
    'bronze': const Color(0xFFCD7F32),
    'copper': const Color(0xFFB87333),
    'champagne': const Color(0xFFF7E7CE),
    'mocha': const Color(0xFF967117),
    'chocolate': const Color(0xFFD2691E),
    'caramel': const Color(0xFFFFD59A),
    'vanilla': const Color(0xFFF3E5AB),
    'cinnamon': const Color(0xFFD2691E),
    'mustard': const Color(0xFFFFDB58),
    'denim': const Color(0xFF1560BD),
    'forest': const Color(0xFF228B22),
    'sky': const Color(0xFF87CEEB),
    'ocean': const Color(0xFF006994),
    'sunset': const Color(0xFFFF4500),
    'sunrise': const Color(0xFFFFDB58),
    'midnight': const Color(0xFF191970),
    'royal': const Color(0xFF4169E1),
    'electric': const Color(0xFF7DF9FF),
    'neon': const Color(0xFF39FF14),
    'pastel': const Color(0xFFFFB347),
    'matte': const Color(0xFF808080),
    'metallic': const Color(0xFFB8860B),
  };
  
  /// Extract dominant colors from an image URL
  static Future<List<ColorInfo>> extractColorsFromUrl(
    String imageUrl, {
    int paletteSize = _defaultPaletteSize,
  }) async {
    try {
      final response = await http.get(Uri.parse(imageUrl));
      if (response.statusCode == 200) {
        return await extractColorsFromBytes(response.bodyBytes, paletteSize: paletteSize);
      }
    } catch (e) {
      debugPrint('Error extracting colors from URL: $e');
    }
    return [];
  }
  
  /// Extract dominant colors from image bytes
  static Future<List<ColorInfo>> extractColorsFromBytes(
    Uint8List bytes, {
    int paletteSize = _defaultPaletteSize,
  }) async {
    try {
      final image = img.decodeImage(bytes);
      if (image == null) return [];
      
      // Resize image for faster processing
      final resizedImage = img.copyResize(
        image,
        width: image.width > _maxImageSize ? _maxImageSize : null,
        height: image.height > _maxImageSize ? _maxImageSize : null,
      );
      
      // Extract colors using quantization
      final colorCounts = <int, int>{};
      
      for (int y = 0; y < resizedImage.height; y++) {
        for (int x = 0; x < resizedImage.width; x++) {
          final pixel = resizedImage.getPixel(x, y);
          final color = _pixelToColor(pixel);
          
          // Skip very dark or very light colors for better results
          if (_isUsableColor(color)) {
            final key = color.value;
            colorCounts[key] = (colorCounts[key] ?? 0) + 1;
          }
        }
      }
      
      // Sort by frequency and take top colors
      final sortedColors = colorCounts.entries.toList()
        ..sort((a, b) => b.value.compareTo(a.value));
      
      final dominantColors = sortedColors
          .take(paletteSize * 2) // Take more colors for clustering
          .map((entry) => Color(entry.key))
          .toList();
      
      // Cluster similar colors
      final clusteredColors = _clusterColors(dominantColors, paletteSize);
      
      // Convert to ColorInfo objects
      return clusteredColors.map((color) => ColorInfo(
        color: color,
        name: getColorName(color),
        percentage: colorCounts[color.value]! / 
                   (resizedImage.width * resizedImage.height),
      )).toList();
      
    } catch (e) {
      debugPrint('Error extracting colors from bytes: $e');
    }
    return [];
  }
  
  /// Convert pixel to Color
  static Color _pixelToColor(img.Pixel pixel) {
    return Color.fromARGB(
      pixel.a.toInt(),
      pixel.r.toInt(),
      pixel.g.toInt(),
      pixel.b.toInt(),
    );
  }
  
  /// Check if color is usable (not too dark, light, or desaturated)
  static bool _isUsableColor(Color color) {
    final hsl = HSLColor.fromColor(color);
    
    // Skip very dark colors
    if (hsl.lightness < 0.1) return false;
    
    // Skip very light colors
    if (hsl.lightness > 0.95) return false;
    
    // Skip very desaturated colors
    if (hsl.saturation < 0.1) return false;
    
    return true;
  }
  
  /// Cluster similar colors to reduce palette size
  static List<Color> _clusterColors(List<Color> colors, int targetSize) {
    if (colors.length <= targetSize) return colors;
    
    final clusters = <List<Color>>[];
    final usedColors = <bool>[...List.filled(colors.length, false)];
    
    while (clusters.length < targetSize && usedColors.contains(false)) {
      final cluster = <Color>[];
      final seedIndex = usedColors.indexOf(false);
      
      if (seedIndex == -1) break;
      
      final seedColor = colors[seedIndex];
      cluster.add(seedColor);
      usedColors[seedIndex] = true;
      
      // Find similar colors
      for (int i = 0; i < colors.length; i++) {
        if (usedColors[i]) continue;
        
        if (_getColorDistance(seedColor, colors[i]) < 50) {
          cluster.add(colors[i]);
          usedColors[i] = true;
        }
      }
      
      clusters.add(cluster);
    }
    
    // Calculate average color for each cluster
    return clusters.map((cluster) => _getAverageColor(cluster)).toList();
  }
  
  /// Get average color from a list of colors
  static Color _getAverageColor(List<Color> colors) {
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
  
  /// Get color name from RGB value
  static String getColorName(Color color) {
    double minDistance = double.infinity;
    String closestName = 'unknown';
    
    for (final entry in _colorMap.entries) {
      final distance = _getColorDistance(color, entry.value);
      if (distance < minDistance) {
        minDistance = distance;
        closestName = entry.key;
      }
    }
    
    return closestName;
  }
  
  /// Get color from name
  static Color? getColorFromName(String name) {
    return _colorMap[name.toLowerCase()];
  }
  
  /// Calculate distance between two colors
  static double _getColorDistance(Color color1, Color color2) {
    final r1 = color1.red;
    final g1 = color1.green;
    final b1 = color1.blue;
    final r2 = color2.red;
    final g2 = color2.green;
    final b2 = color2.blue;
    
    // Euclidean distance in RGB space
    return ((r1 - r2) * (r1 - r2) + 
            (g1 - g2) * (g1 - g2) + 
            (b1 - b2) * (b1 - b2)).toDouble();
  }
  
  /// Find colors that match well with the given color
  static List<ColorInfo> findMatchingColors(
    Color targetColor, {
    int maxResults = 10,
    double maxDistance = 100,
  }) {
    final matchingColors = <ColorInfo>[];
    
    for (final entry in _colorMap.entries) {
      final distance = _getColorDistance(targetColor, entry.value);
      if (distance <= maxDistance) {
        matchingColors.add(ColorInfo(
          color: entry.value,
          name: entry.key,
          percentage: 1.0 - (distance / maxDistance),
        ));
      }
    }
    
    matchingColors.sort((a, b) => b.percentage.compareTo(a.percentage));
    return matchingColors.take(maxResults).toList();
  }
  
  /// Get complementary colors
  static List<Color> getComplementaryColors(Color color) {
    final hsl = HSLColor.fromColor(color);
    
    return [
      // Complementary (opposite on color wheel)
      hsl.withHue((hsl.hue + 180) % 360).toColor(),
      
      // Triadic (120 degrees apart)
      hsl.withHue((hsl.hue + 120) % 360).toColor(),
      hsl.withHue((hsl.hue + 240) % 360).toColor(),
      
      // Analogous (adjacent colors)
      hsl.withHue((hsl.hue + 30) % 360).toColor(),
      hsl.withHue((hsl.hue - 30) % 360).toColor(),
    ];
  }
  
  /// Get seasonal color palette
  static List<Color> getSeasonalPalette(Season season) {
    switch (season) {
      case Season.spring:
        return [
          const Color(0xFF98FB98), // mint green
          const Color(0xFFFFB6C1), // light pink
          const Color(0xFFFFFF99), // light yellow
          const Color(0xFF87CEEB), // sky blue
          const Color(0xFFDDA0DD), // plum
          const Color(0xFFF0E68C), // khaki
        ];
      case Season.summer:
        return [
          const Color(0xFF00CED1), // dark turquoise
          const Color(0xFFFF6347), // tomato
          const Color(0xFFFFD700), // gold
          const Color(0xFF32CD32), // lime green
          const Color(0xFFFF1493), // deep pink
          const Color(0xFF00BFFF), // deep sky blue
        ];
      case Season.autumn:
        return [
          const Color(0xFFD2691E), // chocolate
          const Color(0xFFB22222), // firebrick
          const Color(0xFFDAA520), // goldenrod
          const Color(0xFF8B4513), // saddle brown
          const Color(0xFFCD853F), // peru
          const Color(0xFFA0522D), // sienna
        ];
      case Season.winter:
        return [
          const Color(0xFF2F4F4F), // dark slate gray
          const Color(0xFF483D8B), // dark slate blue
          const Color(0xFF8B0000), // dark red
          const Color(0xFF006400), // dark green
          const Color(0xFF4B0082), // indigo
          const Color(0xFF191970), // midnight blue
        ];
    }
  }
  
  /// Get all available color names
  static List<String> getAllColorNames() {
    return _colorMap.keys.toList()..sort();
  }
  
  /// Search colors by name
  static List<ColorInfo> searchColorsByName(String query) {
    final results = <ColorInfo>[];
    final lowerQuery = query.toLowerCase();
    
    for (final entry in _colorMap.entries) {
      if (entry.key.contains(lowerQuery)) {
        results.add(ColorInfo(
          color: entry.value,
          name: entry.key,
          percentage: entry.key.startsWith(lowerQuery) ? 1.0 : 0.8,
        ));
      }
    }
    
    results.sort((a, b) => b.percentage.compareTo(a.percentage));
    return results;
  }
}

/// Color information with metadata
class ColorInfo {
  final Color color;
  final String name;
  final double percentage;
  
  const ColorInfo({
    required this.color,
    required this.name,
    required this.percentage,
  });
  
  @override
  String toString() => 'ColorInfo(name: $name, percentage: ${(percentage * 100).toStringAsFixed(1)}%)';
}

/// Seasons for color palettes
enum Season {
  spring,
  summer,
  autumn,
  winter,
}

extension SeasonExtension on Season {
  String get displayName {
    switch (this) {
      case Season.spring:
        return 'Spring';
      case Season.summer:
        return 'Summer';
      case Season.autumn:
        return 'Autumn';
      case Season.winter:
        return 'Winter';
    }
  }
  
  String get emoji {
    switch (this) {
      case Season.spring:
        return '🌸';
      case Season.summer:
        return '☀️';
      case Season.autumn:
        return '🍂';
      case Season.winter:
        return '❄️';
    }
  }
}