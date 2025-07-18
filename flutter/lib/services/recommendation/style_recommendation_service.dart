import 'package:flutter/material.dart';
import 'package:koutu/data/models/garment/garment_model.dart';
import 'package:koutu/data/models/user/user_model.dart';
import 'package:koutu/services/color/color_palette_service.dart';
import 'dart:math' as math;

/// AI-powered style recommendation service
class StyleRecommendationService {
  static const int _maxRecommendations = 20;
  static const double _styleScoreThreshold = 0.3;
  
  /// Generate style recommendations based on user preferences and garment history
  static List<StyleRecommendation> generateRecommendations(
    List<GarmentModel> allGarments,
    UserModel user, {
    int maxResults = _maxRecommendations,
    RecommendationType type = RecommendationType.all,
  }) {
    final recommendations = <StyleRecommendation>[];
    
    // Analyze user preferences
    final userProfile = _analyzeUserProfile(allGarments, user);
    
    // Generate different types of recommendations
    switch (type) {
      case RecommendationType.all:
        recommendations.addAll(_generateOutfitRecommendations(allGarments, userProfile));
        recommendations.addAll(_generateSimilarItemRecommendations(allGarments, userProfile));
        recommendations.addAll(_generateColorMatchRecommendations(allGarments, userProfile));
        recommendations.addAll(_generateSeasonalRecommendations(allGarments, userProfile));
        break;
      case RecommendationType.outfits:
        recommendations.addAll(_generateOutfitRecommendations(allGarments, userProfile));
        break;
      case RecommendationType.similar:
        recommendations.addAll(_generateSimilarItemRecommendations(allGarments, userProfile));
        break;
      case RecommendationType.colorMatch:
        recommendations.addAll(_generateColorMatchRecommendations(allGarments, userProfile));
        break;
      case RecommendationType.seasonal:
        recommendations.addAll(_generateSeasonalRecommendations(allGarments, userProfile));
        break;
    }
    
    // Sort by relevance score and return top results
    recommendations.sort((a, b) => b.relevanceScore.compareTo(a.relevanceScore));
    return recommendations.take(maxResults).toList();
  }
  
  /// Analyze user profile to understand preferences
  static UserStyleProfile _analyzeUserProfile(
    List<GarmentModel> garments,
    UserModel user,
  ) {
    final profile = UserStyleProfile();
    
    // Analyze color preferences
    final colorFrequency = <String, int>{};
    final brandFrequency = <String, int>{};
    final categoryFrequency = <String, int>{};
    final tagFrequency = <String, int>{};
    
    int totalWearCount = 0;
    
    for (final garment in garments) {
      final wearWeight = garment.wearCount + 1; // Add 1 to avoid zero weight
      totalWearCount += wearWeight;
      
      // Color preferences
      for (final color in garment.colors) {
        colorFrequency[color] = (colorFrequency[color] ?? 0) + wearWeight;
      }
      
      // Brand preferences
      if (garment.brand != null) {
        brandFrequency[garment.brand!] = (brandFrequency[garment.brand!] ?? 0) + wearWeight;
      }
      
      // Category preferences
      categoryFrequency[garment.category] = (categoryFrequency[garment.category] ?? 0) + wearWeight;
      
      // Tag preferences
      for (final tag in garment.tags) {
        tagFrequency[tag] = (tagFrequency[tag] ?? 0) + wearWeight;
      }
    }
    
    // Calculate preference scores (0.0 to 1.0)
    if (totalWearCount > 0) {
      profile.preferredColors = colorFrequency.entries
          .map((e) => StylePreference(e.key, e.value / totalWearCount))
          .toList()
        ..sort((a, b) => b.score.compareTo(a.score));
        
      profile.preferredBrands = brandFrequency.entries
          .map((e) => StylePreference(e.key, e.value / totalWearCount))
          .toList()
        ..sort((a, b) => b.score.compareTo(a.score));
        
      profile.preferredCategories = categoryFrequency.entries
          .map((e) => StylePreference(e.key, e.value / totalWearCount))
          .toList()
        ..sort((a, b) => b.score.compareTo(a.score));
        
      profile.preferredTags = tagFrequency.entries
          .map((e) => StylePreference(e.key, e.value / totalWearCount))
          .toList()
        ..sort((a, b) => b.score.compareTo(a.score));
    }
    
    // Analyze style patterns
    profile.averageWearFrequency = totalWearCount / garments.length;
    profile.totalGarments = garments.length;
    
    return profile;
  }
  
  /// Generate outfit combination recommendations
  static List<StyleRecommendation> _generateOutfitRecommendations(
    List<GarmentModel> garments,
    UserStyleProfile profile,
  ) {
    final recommendations = <StyleRecommendation>[];
    
    // Group garments by category
    final garmentsByCategory = <String, List<GarmentModel>>{};
    for (final garment in garments) {
      garmentsByCategory[garment.category] ??= [];
      garmentsByCategory[garment.category]!.add(garment);
    }
    
    // Generate outfit combinations
    final tops = garmentsByCategory['tops'] ?? [];
    final bottoms = garmentsByCategory['bottoms'] ?? [];
    final outerwear = garmentsByCategory['outerwear'] ?? [];
    
    // Generate top + bottom combinations
    for (final top in tops.take(10)) {
      for (final bottom in bottoms.take(10)) {
        final outfit = [top, bottom];
        final score = _calculateOutfitScore(outfit, profile);
        
        if (score > _styleScoreThreshold) {
          recommendations.add(StyleRecommendation(
            id: 'outfit_${top.id}_${bottom.id}',
            type: RecommendationType.outfits,
            title: 'Smart Outfit Combo',
            description: 'Perfect pairing of ${top.name} with ${bottom.name}',
            garments: outfit,
            relevanceScore: score,
            reason: _generateOutfitReason(outfit, profile),
          ));
        }
      }
    }
    
    // Generate outerwear combinations
    for (final outer in outerwear.take(5)) {
      for (final top in tops.take(5)) {
        for (final bottom in bottoms.take(5)) {
          final outfit = [outer, top, bottom];
          final score = _calculateOutfitScore(outfit, profile);
          
          if (score > _styleScoreThreshold) {
            recommendations.add(StyleRecommendation(
              id: 'layered_${outer.id}_${top.id}_${bottom.id}',
              type: RecommendationType.outfits,
              title: 'Layered Look',
              description: 'Stylish layering with ${outer.name}',
              garments: outfit,
              relevanceScore: score,
              reason: _generateOutfitReason(outfit, profile),
            ));
          }
        }
      }
    }
    
    return recommendations;
  }
  
  /// Generate recommendations for similar items
  static List<StyleRecommendation> _generateSimilarItemRecommendations(
    List<GarmentModel> garments,
    UserStyleProfile profile,
  ) {
    final recommendations = <StyleRecommendation>[];
    
    // Find items similar to frequently worn pieces
    final favoriteGarments = garments
        .where((g) => g.wearCount > profile.averageWearFrequency)
        .take(10)
        .toList();
    
    for (final favorite in favoriteGarments) {
      final similarItems = _findSimilarGarments(favorite, garments, maxResults: 5);
      
      for (final similar in similarItems) {
        final score = _calculateSimilarityScore(favorite, similar, profile);
        
        if (score > _styleScoreThreshold) {
          recommendations.add(StyleRecommendation(
            id: 'similar_${favorite.id}_${similar.id}',
            type: RecommendationType.similar,
            title: 'You Might Also Like',
            description: 'Similar to your favorite ${favorite.name}',
            garments: [similar],
            relevanceScore: score,
            reason: _generateSimilarityReason(favorite, similar),
          ));
        }
      }
    }
    
    return recommendations;
  }
  
  /// Generate color matching recommendations
  static List<StyleRecommendation> _generateColorMatchRecommendations(
    List<GarmentModel> garments,
    UserStyleProfile profile,
  ) {
    final recommendations = <StyleRecommendation>[];
    
    // Get user's preferred colors
    final topColors = profile.preferredColors.take(5).toList();
    
    for (final colorPref in topColors) {
      final colorName = colorPref.value;
      final targetColor = ColorPaletteService.getColorFromName(colorName);
      
      if (targetColor != null) {
        // Find complementary colors
        final complementaryColors = ColorPaletteService.getComplementaryColors(targetColor);
        
        for (final compColor in complementaryColors) {
          final compColorName = ColorPaletteService.getColorName(compColor);
          
          // Find garments with complementary colors
          final matchingGarments = garments
              .where((g) => g.colors.contains(compColorName))
              .take(5)
              .toList();
          
          for (final garment in matchingGarments) {
            final score = colorPref.score * 0.8; // Slightly lower than direct preference
            
            if (score > _styleScoreThreshold) {
              recommendations.add(StyleRecommendation(
                id: 'color_match_${colorName}_${garment.id}',
                type: RecommendationType.colorMatch,
                title: 'Perfect Color Match',
                description: '${garment.name} complements your ${colorName} pieces',
                garments: [garment],
                relevanceScore: score,
                reason: 'This ${compColorName} piece creates a beautiful harmony with your preferred ${colorName} items',
              ));
            }
          }
        }
      }
    }
    
    return recommendations;
  }
  
  /// Generate seasonal recommendations
  static List<StyleRecommendation> _generateSeasonalRecommendations(
    List<GarmentModel> garments,
    UserStyleProfile profile,
  ) {
    final recommendations = <StyleRecommendation>[];
    final currentSeason = _getCurrentSeason();
    final seasonalPalette = ColorPaletteService.getSeasonalPalette(currentSeason);
    
    // Find garments that match seasonal colors
    for (final garment in garments) {
      double seasonalScore = 0.0;
      
      for (final colorName in garment.colors) {
        final garmentColor = ColorPaletteService.getColorFromName(colorName);
        if (garmentColor != null) {
          for (final seasonalColor in seasonalPalette) {
            final distance = _calculateColorDistance(garmentColor, seasonalColor);
            if (distance < 50) { // Close color match
              seasonalScore += 0.2;
            }
          }
        }
      }
      
      if (seasonalScore > _styleScoreThreshold) {
        recommendations.add(StyleRecommendation(
          id: 'seasonal_${currentSeason.name}_${garment.id}',
          type: RecommendationType.seasonal,
          title: '${currentSeason.displayName} Perfect',
          description: '${garment.name} is trending this ${currentSeason.displayName.toLowerCase()}',
          garments: [garment],
          relevanceScore: seasonalScore,
          reason: 'This piece features ${currentSeason.displayName.toLowerCase()} colors that are perfect for the current season',
        ));
      }
    }
    
    return recommendations;
  }
  
  /// Calculate outfit combination score
  static double _calculateOutfitScore(
    List<GarmentModel> outfit,
    UserStyleProfile profile,
  ) {
    double score = 0.0;
    
    // Color harmony score
    final outfitColors = outfit.expand((g) => g.colors).toList();
    score += _calculateColorHarmonyScore(outfitColors);
    
    // User preference score
    for (final garment in outfit) {
      // Brand preference
      if (garment.brand != null) {
        final brandPref = profile.preferredBrands
            .firstWhere((p) => p.value == garment.brand, orElse: () => StylePreference('', 0.0));
        score += brandPref.score * 0.1;
      }
      
      // Category preference
      final categoryPref = profile.preferredCategories
          .firstWhere((p) => p.value == garment.category, orElse: () => StylePreference('', 0.0));
      score += categoryPref.score * 0.1;
      
      // Color preferences
      for (final color in garment.colors) {
        final colorPref = profile.preferredColors
            .firstWhere((p) => p.value == color, orElse: () => StylePreference('', 0.0));
        score += colorPref.score * 0.2;
      }
    }
    
    return math.min(score, 1.0); // Cap at 1.0
  }
  
  /// Calculate color harmony score for outfit
  static double _calculateColorHarmonyScore(List<String> colors) {
    if (colors.length < 2) return 0.5; // Neutral score for single color
    
    final colorObjects = colors
        .map((name) => ColorPaletteService.getColorFromName(name))
        .where((color) => color != null)
        .cast<Color>()
        .toList();
    
    if (colorObjects.isEmpty) return 0.0;
    
    double harmonyScore = 0.0;
    int comparisons = 0;
    
    for (int i = 0; i < colorObjects.length; i++) {
      for (int j = i + 1; j < colorObjects.length; j++) {
        final color1 = colorObjects[i];
        final color2 = colorObjects[j];
        
        // Calculate color harmony based on HSL relationships
        final hsl1 = HSLColor.fromColor(color1);
        final hsl2 = HSLColor.fromColor(color2);
        
        final hueDifference = (hsl1.hue - hsl2.hue).abs();
        final satDifference = (hsl1.saturation - hsl2.saturation).abs();
        final lightDifference = (hsl1.lightness - hsl2.lightness).abs();
        
        // Good harmony: complementary (180°), triadic (120°), or analogous (30°)
        if ((hueDifference >= 170 && hueDifference <= 190) || // Complementary
            (hueDifference >= 110 && hueDifference <= 130) || // Triadic
            (hueDifference >= 240 && hueDifference <= 250) || // Triadic
            (hueDifference >= 20 && hueDifference <= 40)) {   // Analogous
          harmonyScore += 0.3;
        }
        
        // Penalize extreme differences in saturation and lightness
        if (satDifference > 0.7 || lightDifference > 0.7) {
          harmonyScore -= 0.1;
        }
        
        comparisons++;
      }
    }
    
    return comparisons > 0 ? harmonyScore / comparisons : 0.0;
  }
  
  /// Calculate similarity score between two garments
  static double _calculateSimilarityScore(
    GarmentModel garment1,
    GarmentModel garment2,
    UserStyleProfile profile,
  ) {
    double score = 0.0;
    
    // Category similarity
    if (garment1.category == garment2.category) {
      score += 0.3;
    }
    
    // Brand similarity
    if (garment1.brand != null && garment1.brand == garment2.brand) {
      score += 0.2;
    }
    
    // Color similarity
    final commonColors = garment1.colors.toSet().intersection(garment2.colors.toSet());
    score += commonColors.length * 0.1;
    
    // Tag similarity
    final commonTags = garment1.tags.toSet().intersection(garment2.tags.toSet());
    score += commonTags.length * 0.1;
    
    return math.min(score, 1.0);
  }
  
  /// Find similar garments to a given garment
  static List<GarmentModel> _findSimilarGarments(
    GarmentModel target,
    List<GarmentModel> allGarments, {
    int maxResults = 10,
  }) {
    final similarities = allGarments
        .where((g) => g.id != target.id)
        .map((g) => _SimilarityPair(g, _calculateBasicSimilarity(target, g)))
        .where((pair) => pair.similarity > 0.2)
        .toList();
    
    similarities.sort((a, b) => b.similarity.compareTo(a.similarity));
    return similarities.take(maxResults).map((pair) => pair.garment).toList();
  }
  
  /// Calculate basic similarity between two garments
  static double _calculateBasicSimilarity(GarmentModel g1, GarmentModel g2) {
    double score = 0.0;
    
    if (g1.category == g2.category) score += 0.4;
    if (g1.brand == g2.brand) score += 0.2;
    
    final commonColors = g1.colors.toSet().intersection(g2.colors.toSet());
    score += commonColors.length * 0.1;
    
    final commonTags = g1.tags.toSet().intersection(g2.tags.toSet());
    score += commonTags.length * 0.1;
    
    return score;
  }
  
  /// Calculate distance between two colors
  static double _calculateColorDistance(Color color1, Color color2) {
    final r1 = color1.red;
    final g1 = color1.green;
    final b1 = color1.blue;
    final r2 = color2.red;
    final g2 = color2.green;
    final b2 = color2.blue;
    
    return math.sqrt((r1 - r2) * (r1 - r2) + (g1 - g2) * (g1 - g2) + (b1 - b2) * (b1 - b2));
  }
  
  /// Get current season based on month
  static Season _getCurrentSeason() {
    final month = DateTime.now().month;
    
    if (month >= 3 && month <= 5) return Season.spring;
    if (month >= 6 && month <= 8) return Season.summer;
    if (month >= 9 && month <= 11) return Season.autumn;
    return Season.winter;
  }
  
  /// Generate reason for outfit recommendation
  static String _generateOutfitReason(
    List<GarmentModel> outfit,
    UserStyleProfile profile,
  ) {
    final reasons = <String>[];
    
    // Color harmony
    final colors = outfit.expand((g) => g.colors).toSet();
    if (colors.length > 1) {
      reasons.add('Great color combination');
    }
    
    // User preferences
    final hasPreferredBrand = outfit.any((g) => 
        profile.preferredBrands.any((p) => p.value == g.brand && p.score > 0.1));
    if (hasPreferredBrand) {
      reasons.add('Features your favorite brands');
    }
    
    final hasPreferredColors = outfit.any((g) => 
        g.colors.any((c) => profile.preferredColors.any((p) => p.value == c && p.score > 0.1)));
    if (hasPreferredColors) {
      reasons.add('Matches your color preferences');
    }
    
    return reasons.isNotEmpty ? reasons.join(' • ') : 'Stylish combination';
  }
  
  /// Generate reason for similarity recommendation
  static String _generateSimilarityReason(GarmentModel favorite, GarmentModel similar) {
    final reasons = <String>[];
    
    if (favorite.category == similar.category) {
      reasons.add('Same category');
    }
    
    if (favorite.brand == similar.brand) {
      reasons.add('Same brand');
    }
    
    final commonColors = favorite.colors.toSet().intersection(similar.colors.toSet());
    if (commonColors.isNotEmpty) {
      reasons.add('Similar colors');
    }
    
    return reasons.isNotEmpty ? reasons.join(' • ') : 'Similar style';
  }
}

/// User style profile for personalized recommendations
class UserStyleProfile {
  List<StylePreference> preferredColors = [];
  List<StylePreference> preferredBrands = [];
  List<StylePreference> preferredCategories = [];
  List<StylePreference> preferredTags = [];
  
  double averageWearFrequency = 0.0;
  int totalGarments = 0;
}

/// Style preference with score
class StylePreference {
  final String value;
  final double score;
  
  const StylePreference(this.value, this.score);
}

/// Style recommendation result
class StyleRecommendation {
  final String id;
  final RecommendationType type;
  final String title;
  final String description;
  final List<GarmentModel> garments;
  final double relevanceScore;
  final String reason;
  
  const StyleRecommendation({
    required this.id,
    required this.type,
    required this.title,
    required this.description,
    required this.garments,
    required this.relevanceScore,
    required this.reason,
  });
}

/// Types of recommendations
enum RecommendationType {
  all,
  outfits,
  similar,
  colorMatch,
  seasonal,
}

extension RecommendationTypeExtension on RecommendationType {
  String get displayName {
    switch (this) {
      case RecommendationType.all:
        return 'All Recommendations';
      case RecommendationType.outfits:
        return 'Outfit Combos';
      case RecommendationType.similar:
        return 'Similar Items';
      case RecommendationType.colorMatch:
        return 'Color Matches';
      case RecommendationType.seasonal:
        return 'Seasonal Picks';
    }
  }
  
  IconData get icon {
    switch (this) {
      case RecommendationType.all:
        return Icons.auto_awesome;
      case RecommendationType.outfits:
        return Icons.checkroom;
      case RecommendationType.similar:
        return Icons.favorite;
      case RecommendationType.colorMatch:
        return Icons.palette;
      case RecommendationType.seasonal:
        return Icons.wb_sunny;
    }
  }
}

/// Helper class for similarity calculations
class _SimilarityPair {
  final GarmentModel garment;
  final double similarity;
  
  const _SimilarityPair(this.garment, this.similarity);
}