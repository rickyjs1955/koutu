import 'package:flutter/material.dart';
import 'package:koutu/data/models/garment/garment_model.dart';
import 'package:koutu/services/color/color_palette_service.dart';
import 'dart:math' as math;

/// Service for visual similarity search between garments
class VisualSimilarityService {
  static const double _colorWeight = 0.3;
  static const double _categoryWeight = 0.25;
  static const double _styleWeight = 0.2;
  static const double _materialWeight = 0.15;
  static const double _patternWeight = 0.1;
  static const double _minSimilarityThreshold = 0.2;
  
  /// Find visually similar garments to a target garment
  static List<VisualSimilarityResult> findSimilarGarments(
    GarmentModel targetGarment,
    List<GarmentModel> allGarments, {
    int maxResults = 20,
    double minSimilarity = _minSimilarityThreshold,
  }) {
    final results = <VisualSimilarityResult>[];
    
    // Extract visual features from target garment
    final targetFeatures = _extractVisualFeatures(targetGarment);
    
    for (final garment in allGarments) {
      // Skip the target garment itself
      if (garment.id == targetGarment.id) continue;
      
      // Extract features from candidate garment
      final candidateFeatures = _extractVisualFeatures(garment);
      
      // Calculate similarity score
      final similarityScore = _calculateSimilarityScore(
        targetFeatures,
        candidateFeatures,
      );
      
      if (similarityScore >= minSimilarity) {
        results.add(VisualSimilarityResult(
          garment: garment,
          similarityScore: similarityScore,
          targetGarment: targetGarment,
          similarityReasons: _generateSimilarityReasons(
            targetFeatures,
            candidateFeatures,
          ),
        ));
      }
    }
    
    // Sort by similarity score and return top results
    results.sort((a, b) => b.similarityScore.compareTo(a.similarityScore));
    return results.take(maxResults).toList();
  }
  
  /// Find garments with similar colors
  static List<VisualSimilarityResult> findSimilarColors(
    List<String> targetColors,
    List<GarmentModel> allGarments, {
    int maxResults = 15,
    double colorThreshold = 0.3,
  }) {
    final results = <VisualSimilarityResult>[];
    
    // Convert target colors to Color objects
    final targetColorObjects = targetColors
        .map((name) => ColorPaletteService.getColorFromName(name))
        .where((color) => color != null)
        .cast<Color>()
        .toList();
    
    if (targetColorObjects.isEmpty) return results;
    
    for (final garment in allGarments) {
      // Convert garment colors to Color objects
      final garmentColorObjects = garment.colors
          .map((name) => ColorPaletteService.getColorFromName(name))
          .where((color) => color != null)
          .cast<Color>()
          .toList();
      
      if (garmentColorObjects.isEmpty) continue;
      
      // Calculate color similarity
      final colorSimilarity = _calculateColorSimilarity(
        targetColorObjects,
        garmentColorObjects,
      );
      
      if (colorSimilarity >= colorThreshold) {
        results.add(VisualSimilarityResult(
          garment: garment,
          similarityScore: colorSimilarity,
          targetGarment: null,
          similarityReasons: ['Similar color palette'],
        ));
      }
    }
    
    results.sort((a, b) => b.similarityScore.compareTo(a.similarityScore));
    return results.take(maxResults).toList();
  }
  
  /// Find garments with similar patterns
  static List<VisualSimilarityResult> findSimilarPatterns(
    String targetPattern,
    List<GarmentModel> allGarments, {
    int maxResults = 10,
  }) {
    final results = <VisualSimilarityResult>[];
    final targetPatternNormalized = _normalizePattern(targetPattern);
    
    for (final garment in allGarments) {
      final patternSimilarity = _calculatePatternSimilarity(
        targetPatternNormalized,
        garment.tags,
      );
      
      if (patternSimilarity > 0.5) {
        results.add(VisualSimilarityResult(
          garment: garment,
          similarityScore: patternSimilarity,
          targetGarment: null,
          similarityReasons: ['Similar pattern: $targetPattern'],
        ));
      }
    }
    
    results.sort((a, b) => b.similarityScore.compareTo(a.similarityScore));
    return results.take(maxResults).toList();
  }
  
  /// Group garments by visual similarity
  static Map<String, List<GarmentModel>> groupBySimilarity(
    List<GarmentModel> garments, {
    double similarityThreshold = 0.6,
  }) {
    final groups = <String, List<GarmentModel>>{};
    final processed = <String>{};
    
    for (int i = 0; i < garments.length; i++) {
      final garment = garments[i];
      
      if (processed.contains(garment.id)) continue;
      
      final groupKey = 'group_${groups.length}';
      groups[groupKey] = [garment];
      processed.add(garment.id);
      
      // Find similar garments
      final similarGarments = findSimilarGarments(
        garment,
        garments,
        minSimilarity: similarityThreshold,
      );
      
      for (final similar in similarGarments) {
        if (!processed.contains(similar.garment.id)) {
          groups[groupKey]!.add(similar.garment);
          processed.add(similar.garment.id);
        }
      }
    }
    
    return groups;
  }
  
  /// Extract visual features from a garment
  static VisualFeatures _extractVisualFeatures(GarmentModel garment) {
    return VisualFeatures(
      colors: garment.colors,
      category: garment.category,
      tags: garment.tags,
      brand: garment.brand,
    );
  }
  
  /// Calculate overall similarity score between two sets of features
  static double _calculateSimilarityScore(
    VisualFeatures target,
    VisualFeatures candidate,
  ) {
    // Color similarity
    final colorSimilarity = _calculateColorSimilarityFromNames(
      target.colors,
      candidate.colors,
    );
    
    // Category similarity
    final categorySimilarity = _calculateCategorySimilarity(
      target.category,
      candidate.category,
    );
    
    // Style similarity (from tags)
    final styleSimilarity = _calculateStyleSimilarity(
      target.tags,
      candidate.tags,
    );
    
    // Material similarity
    final materialSimilarity = _calculateMaterialSimilarity(
      target.tags,
      candidate.tags,
    );
    
    // Pattern similarity
    final patternSimilarity = _calculatePatternSimilarityFromTags(
      target.tags,
      candidate.tags,
    );
    
    // Weighted average
    return (colorSimilarity * _colorWeight) +
           (categorySimilarity * _categoryWeight) +
           (styleSimilarity * _styleWeight) +
           (materialSimilarity * _materialWeight) +
           (patternSimilarity * _patternWeight);
  }
  
  /// Calculate color similarity between two color lists
  static double _calculateColorSimilarity(
    List<Color> colors1,
    List<Color> colors2,
  ) {
    if (colors1.isEmpty || colors2.isEmpty) return 0.0;
    
    double totalSimilarity = 0.0;
    int comparisons = 0;
    
    for (final color1 in colors1) {
      double maxSimilarity = 0.0;
      
      for (final color2 in colors2) {
        final similarity = _calculateSingleColorSimilarity(color1, color2);
        maxSimilarity = math.max(maxSimilarity, similarity);
      }
      
      totalSimilarity += maxSimilarity;
      comparisons++;
    }
    
    return comparisons > 0 ? totalSimilarity / comparisons : 0.0;
  }
  
  /// Calculate color similarity from color names
  static double _calculateColorSimilarityFromNames(
    List<String> colors1,
    List<String> colors2,
  ) {
    final colorObjects1 = colors1
        .map((name) => ColorPaletteService.getColorFromName(name))
        .where((color) => color != null)
        .cast<Color>()
        .toList();
    
    final colorObjects2 = colors2
        .map((name) => ColorPaletteService.getColorFromName(name))
        .where((color) => color != null)
        .cast<Color>()
        .toList();
    
    return _calculateColorSimilarity(colorObjects1, colorObjects2);
  }
  
  /// Calculate similarity between two individual colors
  static double _calculateSingleColorSimilarity(Color color1, Color color2) {
    // Convert to HSL for better perceptual similarity
    final hsl1 = HSLColor.fromColor(color1);
    final hsl2 = HSLColor.fromColor(color2);
    
    // Calculate differences
    final hueDiff = (hsl1.hue - hsl2.hue).abs();
    final satDiff = (hsl1.saturation - hsl2.saturation).abs();
    final lightDiff = (hsl1.lightness - hsl2.lightness).abs();
    
    // Normalize hue difference (circular)
    final normalizedHueDiff = math.min(hueDiff, 360 - hueDiff) / 180;
    
    // Weighted similarity (hue is most important)
    final similarity = 1.0 - (
      (normalizedHueDiff * 0.6) +
      (satDiff * 0.2) +
      (lightDiff * 0.2)
    );
    
    return math.max(0.0, similarity);
  }
  
  /// Calculate category similarity
  static double _calculateCategorySimilarity(String category1, String category2) {
    if (category1.toLowerCase() == category2.toLowerCase()) return 1.0;
    
    // Check for related categories
    final relatedCategories = _getRelatedCategories(category1.toLowerCase());
    if (relatedCategories.contains(category2.toLowerCase())) {
      return 0.7;
    }
    
    return 0.0;
  }
  
  /// Calculate style similarity from tags
  static double _calculateStyleSimilarity(List<String> tags1, List<String> tags2) {
    final styleTags1 = _extractStyleTags(tags1);
    final styleTags2 = _extractStyleTags(tags2);
    
    if (styleTags1.isEmpty && styleTags2.isEmpty) return 0.5;
    if (styleTags1.isEmpty || styleTags2.isEmpty) return 0.0;
    
    final intersection = styleTags1.toSet().intersection(styleTags2.toSet());
    final union = styleTags1.toSet().union(styleTags2.toSet());
    
    return intersection.length / union.length;
  }
  
  /// Calculate material similarity from tags
  static double _calculateMaterialSimilarity(List<String> tags1, List<String> tags2) {
    final materialTags1 = _extractMaterialTags(tags1);
    final materialTags2 = _extractMaterialTags(tags2);
    
    if (materialTags1.isEmpty && materialTags2.isEmpty) return 0.5;
    if (materialTags1.isEmpty || materialTags2.isEmpty) return 0.0;
    
    final intersection = materialTags1.toSet().intersection(materialTags2.toSet());
    final union = materialTags1.toSet().union(materialTags2.toSet());
    
    return intersection.length / union.length;
  }
  
  /// Calculate pattern similarity from tags
  static double _calculatePatternSimilarityFromTags(List<String> tags1, List<String> tags2) {
    final patternTags1 = _extractPatternTags(tags1);
    final patternTags2 = _extractPatternTags(tags2);
    
    if (patternTags1.isEmpty && patternTags2.isEmpty) return 0.5;
    if (patternTags1.isEmpty || patternTags2.isEmpty) return 0.0;
    
    final intersection = patternTags1.toSet().intersection(patternTags2.toSet());
    final union = patternTags1.toSet().union(patternTags2.toSet());
    
    return intersection.length / union.length;
  }
  
  /// Calculate pattern similarity for a specific pattern
  static double _calculatePatternSimilarity(String targetPattern, List<String> tags) {
    final patternTags = _extractPatternTags(tags);
    
    if (patternTags.contains(targetPattern)) return 1.0;
    
    // Check for similar patterns
    final similarPatterns = _getSimilarPatterns(targetPattern);
    for (final pattern in patternTags) {
      if (similarPatterns.contains(pattern)) return 0.7;
    }
    
    return 0.0;
  }
  
  /// Get related categories for a given category
  static List<String> _getRelatedCategories(String category) {
    final relations = {
      'shirt': ['blouse', 'top', 'tshirt'],
      'blouse': ['shirt', 'top'],
      'top': ['shirt', 'blouse', 'tshirt'],
      'tshirt': ['shirt', 'top'],
      'pants': ['jeans', 'trousers', 'bottoms'],
      'jeans': ['pants', 'trousers', 'bottoms'],
      'trousers': ['pants', 'jeans', 'bottoms'],
      'bottoms': ['pants', 'jeans', 'trousers'],
      'jacket': ['coat', 'outerwear', 'blazer'],
      'coat': ['jacket', 'outerwear'],
      'outerwear': ['jacket', 'coat', 'blazer'],
      'blazer': ['jacket', 'outerwear'],
      'dress': ['gown', 'frock'],
      'gown': ['dress'],
      'skirt': ['mini', 'midi', 'maxi'],
      'shoe': ['shoes', 'footwear'],
      'shoes': ['shoe', 'footwear'],
      'footwear': ['shoe', 'shoes'],
    };
    
    return relations[category] ?? [];
  }
  
  /// Extract style tags from a list of tags
  static List<String> _extractStyleTags(List<String> tags) {
    final styleTags = [
      'casual', 'formal', 'sporty', 'elegant', 'trendy', 'classic', 'vintage',
      'bohemian', 'minimalist', 'edgy', 'romantic', 'preppy', 'grunge',
      'business', 'party', 'date', 'everyday', 'special'
    ];
    
    return tags.where((tag) => styleTags.contains(tag.toLowerCase())).toList();
  }
  
  /// Extract material tags from a list of tags
  static List<String> _extractMaterialTags(List<String> tags) {
    final materialTags = [
      'cotton', 'wool', 'silk', 'linen', 'polyester', 'denim', 'leather',
      'cashmere', 'velvet', 'chiffon', 'satin', 'jersey', 'flannel',
      'corduroy', 'tweed', 'lace', 'mesh', 'knit'
    ];
    
    return tags.where((tag) => materialTags.contains(tag.toLowerCase())).toList();
  }
  
  /// Extract pattern tags from a list of tags
  static List<String> _extractPatternTags(List<String> tags) {
    final patternTags = [
      'solid', 'striped', 'floral', 'geometric', 'abstract', 'polka dot',
      'plaid', 'checkered', 'animal print', 'paisley', 'tribal', 'tropical',
      'chevron', 'herringbone', 'houndstooth', 'argyle', 'camouflage'
    ];
    
    return tags.where((tag) => patternTags.contains(tag.toLowerCase())).toList();
  }
  
  /// Normalize pattern name
  static String _normalizePattern(String pattern) {
    return pattern.toLowerCase().trim();
  }
  
  /// Get similar patterns for a given pattern
  static List<String> _getSimilarPatterns(String pattern) {
    final similarities = {
      'striped': ['plaid', 'checkered', 'chevron'],
      'plaid': ['striped', 'checkered', 'tartan'],
      'checkered': ['plaid', 'striped', 'gingham'],
      'floral': ['tropical', 'botanical', 'rose'],
      'geometric': ['abstract', 'tribal', 'chevron'],
      'polka dot': ['spotted', 'dotted'],
      'animal print': ['leopard', 'zebra', 'snake'],
      'paisley': ['tribal', 'ethnic', 'bohemian'],
    };
    
    return similarities[pattern] ?? [];
  }
  
  /// Generate similarity reasons
  static List<String> _generateSimilarityReasons(
    VisualFeatures target,
    VisualFeatures candidate,
  ) {
    final reasons = <String>[];
    
    // Color similarity
    final colorSimilarity = _calculateColorSimilarityFromNames(
      target.colors,
      candidate.colors,
    );
    if (colorSimilarity > 0.7) {
      reasons.add('Similar color palette');
    }
    
    // Category similarity
    if (target.category.toLowerCase() == candidate.category.toLowerCase()) {
      reasons.add('Same category');
    }
    
    // Style similarity
    final styleTags1 = _extractStyleTags(target.tags);
    final styleTags2 = _extractStyleTags(candidate.tags);
    final commonStyles = styleTags1.toSet().intersection(styleTags2.toSet());
    if (commonStyles.isNotEmpty) {
      reasons.add('Similar style: ${commonStyles.join(', ')}');
    }
    
    // Material similarity
    final materialTags1 = _extractMaterialTags(target.tags);
    final materialTags2 = _extractMaterialTags(candidate.tags);
    final commonMaterials = materialTags1.toSet().intersection(materialTags2.toSet());
    if (commonMaterials.isNotEmpty) {
      reasons.add('Similar material: ${commonMaterials.join(', ')}');
    }
    
    // Pattern similarity
    final patternTags1 = _extractPatternTags(target.tags);
    final patternTags2 = _extractPatternTags(candidate.tags);
    final commonPatterns = patternTags1.toSet().intersection(patternTags2.toSet());
    if (commonPatterns.isNotEmpty) {
      reasons.add('Similar pattern: ${commonPatterns.join(', ')}');
    }
    
    // Brand similarity
    if (target.brand != null && target.brand == candidate.brand) {
      reasons.add('Same brand');
    }
    
    return reasons.isNotEmpty ? reasons : ['Visually similar'];
  }
}

/// Visual features extracted from a garment
class VisualFeatures {
  final List<String> colors;
  final String category;
  final List<String> tags;
  final String? brand;
  
  const VisualFeatures({
    required this.colors,
    required this.category,
    required this.tags,
    this.brand,
  });
}

/// Visual similarity search result
class VisualSimilarityResult {
  final GarmentModel garment;
  final double similarityScore;
  final GarmentModel? targetGarment;
  final List<String> similarityReasons;
  
  const VisualSimilarityResult({
    required this.garment,
    required this.similarityScore,
    this.targetGarment,
    required this.similarityReasons,
  });
}