import 'package:flutter/material.dart';
import 'package:koutu/data/models/garment/garment_model.dart';
import 'package:koutu/services/color/color_palette_service.dart';
import 'dart:math' as math;

/// Service for generating weather-appropriate outfit recommendations
class WeatherOutfitService {
  static const double _temperatureWeight = 0.4;
  static const double _conditionWeight = 0.3;
  static const double _seasonWeight = 0.2;
  static const double _preferenceWeight = 0.1;
  
  /// Generate outfit recommendations based on weather conditions
  static List<WeatherOutfitRecommendation> generateWeatherOutfits(
    List<GarmentModel> garments,
    WeatherCondition weather, {
    int maxResults = 10,
  }) {
    final recommendations = <WeatherOutfitRecommendation>[];
    
    // Filter garments suitable for the weather
    final suitableGarments = _filterGarmentsByWeather(garments, weather);
    
    // Group by category
    final garmentsByCategory = _groupGarmentsByCategory(suitableGarments);
    
    // Generate outfit combinations
    final outfits = _generateOutfitCombinations(garmentsByCategory, weather);
    
    // Score and rank outfits
    for (final outfit in outfits) {
      final score = _calculateWeatherScore(outfit, weather);
      
      if (score > 0.3) { // Minimum threshold
        recommendations.add(WeatherOutfitRecommendation(
          id: _generateOutfitId(outfit),
          garments: outfit,
          weatherScore: score,
          temperature: weather.temperature,
          condition: weather.condition,
          description: _generateOutfitDescription(outfit, weather),
          weatherReason: _generateWeatherReason(outfit, weather),
        ));
      }
    }
    
    // Sort by score and return top results
    recommendations.sort((a, b) => b.weatherScore.compareTo(a.weatherScore));
    return recommendations.take(maxResults).toList();
  }
  
  /// Filter garments suitable for current weather
  static List<GarmentModel> _filterGarmentsByWeather(
    List<GarmentModel> garments,
    WeatherCondition weather,
  ) {
    return garments.where((garment) {
      // Temperature-based filtering
      final tempSuitability = _getTemperatureSuitability(garment, weather.temperature);
      if (tempSuitability < 0.2) return false;
      
      // Condition-based filtering
      final conditionSuitability = _getConditionSuitability(garment, weather.condition);
      if (conditionSuitability < 0.2) return false;
      
      return true;
    }).toList();
  }
  
  /// Get temperature suitability score for a garment
  static double _getTemperatureSuitability(GarmentModel garment, double temperature) {
    // Define temperature ranges for different garment types
    final tempRanges = _getGarmentTemperatureRanges(garment);
    
    if (temperature >= tempRanges['min']! && temperature <= tempRanges['max']!) {
      return 1.0; // Perfect match
    }
    
    // Calculate score based on distance from ideal range
    final distanceFromRange = math.min(
      (temperature - tempRanges['max']!).abs(),
      (temperature - tempRanges['min']!).abs(),
    );
    
    // Decrease score based on distance (more forgiving for slight mismatches)
    return math.max(0.0, 1.0 - (distanceFromRange / 20));
  }
  
  /// Get condition suitability score for a garment
  static double _getConditionSuitability(GarmentModel garment, WeatherType condition) {
    final suitability = _getGarmentWeatherSuitability(garment);
    
    switch (condition) {
      case WeatherType.sunny:
        return suitability['sunny'] ?? 0.5;
      case WeatherType.cloudy:
        return suitability['cloudy'] ?? 0.7;
      case WeatherType.rainy:
        return suitability['rainy'] ?? 0.3;
      case WeatherType.snowy:
        return suitability['snowy'] ?? 0.2;
      case WeatherType.windy:
        return suitability['windy'] ?? 0.6;
      case WeatherType.foggy:
        return suitability['foggy'] ?? 0.6;
    }
  }
  
  /// Get temperature ranges for different garment types
  static Map<String, double> _getGarmentTemperatureRanges(GarmentModel garment) {
    final category = garment.category.toLowerCase();
    final tags = garment.tags.map((t) => t.toLowerCase()).toList();
    
    // Base ranges by category
    Map<String, double> ranges = {'min': 10, 'max': 30}; // Default comfortable range
    
    if (category.contains('outerwear') || category.contains('jacket')) {
      if (tags.contains('winter') || tags.contains('heavy')) {
        ranges = {'min': -10, 'max': 15};
      } else if (tags.contains('light') || tags.contains('windbreaker')) {
        ranges = {'min': 5, 'max': 20};
      } else {
        ranges = {'min': 0, 'max': 18};
      }
    } else if (category.contains('sweater') || category.contains('hoodie')) {
      ranges = {'min': 5, 'max': 20};
    } else if (category.contains('shirt') || category.contains('top')) {
      if (tags.contains('long sleeve')) {
        ranges = {'min': 10, 'max': 25};
      } else if (tags.contains('tank') || tags.contains('sleeveless')) {
        ranges = {'min': 20, 'max': 35};
      } else {
        ranges = {'min': 15, 'max': 30};
      }
    } else if (category.contains('pants') || category.contains('jeans')) {
      if (tags.contains('thick') || tags.contains('winter')) {
        ranges = {'min': -5, 'max': 20};
      } else {
        ranges = {'min': 10, 'max': 35};
      }
    } else if (category.contains('shorts')) {
      ranges = {'min': 18, 'max': 40};
    } else if (category.contains('dress')) {
      if (tags.contains('long sleeve') || tags.contains('winter')) {
        ranges = {'min': 10, 'max': 25};
      } else {
        ranges = {'min': 18, 'max': 35};
      }
    } else if (category.contains('skirt')) {
      ranges = {'min': 15, 'max': 35};
    }
    
    return ranges;
  }
  
  /// Get weather condition suitability for different garment types
  static Map<String, double> _getGarmentWeatherSuitability(GarmentModel garment) {
    final category = garment.category.toLowerCase();
    final tags = garment.tags.map((t) => t.toLowerCase()).toList();
    final materials = garment.tags.where((t) => \n        ['cotton', 'wool', 'polyester', 'silk', 'linen', 'denim', 'leather'].contains(t.toLowerCase())).toList();
    
    Map<String, double> suitability = {\n      'sunny': 0.7,\n      'cloudy': 0.8,\n      'rainy': 0.5,\n      'snowy': 0.4,\n      'windy': 0.6,\n      'foggy': 0.6,\n    };
    
    // Adjust based on category
    if (category.contains('outerwear')) {
      suitability['rainy'] = 0.9;
      suitability['snowy'] = 0.9;
      suitability['windy'] = 0.9;
      if (tags.contains('waterproof') || tags.contains('rain')) {
        suitability['rainy'] = 1.0;
      }
    }
    
    // Adjust based on materials
    for (final material in materials) {
      switch (material.toLowerCase()) {
        case 'cotton':
          suitability['sunny'] = (suitability['sunny']! + 0.2).clamp(0.0, 1.0);
          break;
        case 'wool':
          suitability['snowy'] = (suitability['snowy']! + 0.3).clamp(0.0, 1.0);
          suitability['windy'] = (suitability['windy']! + 0.2).clamp(0.0, 1.0);
          break;
        case 'linen':
          suitability['sunny'] = (suitability['sunny']! + 0.3).clamp(0.0, 1.0);
          suitability['rainy'] = (suitability['rainy']! - 0.2).clamp(0.0, 1.0);
          break;
        case 'leather':
          suitability['rainy'] = (suitability['rainy']! + 0.2).clamp(0.0, 1.0);
          suitability['windy'] = (suitability['windy']! + 0.2).clamp(0.0, 1.0);
          break;
      }
    }
    
    return suitability;
  }
  
  /// Group garments by category for outfit generation
  static Map<String, List<GarmentModel>> _groupGarmentsByCategory(List<GarmentModel> garments) {
    final grouped = <String, List<GarmentModel>>{};
    
    for (final garment in garments) {
      final category = _normalizeCategory(garment.category);
      grouped[category] ??= [];
      grouped[category]!.add(garment);
    }
    
    return grouped;
  }
  
  /// Normalize category names for consistent grouping
  static String _normalizeCategory(String category) {
    final normalized = category.toLowerCase();
    
    if (normalized.contains('top') || normalized.contains('shirt') || 
        normalized.contains('blouse') || normalized.contains('sweater')) {
      return 'tops';
    } else if (normalized.contains('bottom') || normalized.contains('pants') || 
               normalized.contains('jeans') || normalized.contains('shorts')) {
      return 'bottoms';
    } else if (normalized.contains('dress')) {
      return 'dresses';
    } else if (normalized.contains('skirt')) {
      return 'skirts';
    } else if (normalized.contains('outerwear') || normalized.contains('jacket') || 
               normalized.contains('coat')) {
      return 'outerwear';
    } else if (normalized.contains('shoe')) {
      return 'shoes';
    } else if (normalized.contains('accessory')) {
      return 'accessories';
    }
    
    return 'other';
  }
  
  /// Generate outfit combinations based on weather
  static List<List<GarmentModel>> _generateOutfitCombinations(
    Map<String, List<GarmentModel>> garmentsByCategory,
    WeatherCondition weather,
  ) {
    final outfits = <List<GarmentModel>>[];
    
    final tops = garmentsByCategory['tops'] ?? [];
    final bottoms = garmentsByCategory['bottoms'] ?? [];
    final dresses = garmentsByCategory['dresses'] ?? [];
    final skirts = garmentsByCategory['skirts'] ?? [];
    final outerwear = garmentsByCategory['outerwear'] ?? [];
    
    // Generate top + bottom combinations
    for (final top in tops.take(8)) {
      for (final bottom in bottoms.take(8)) {
        final outfit = [top, bottom];
        
        // Add outerwear if temperature is low
        if (weather.temperature < 15 && outerwear.isNotEmpty) {
          for (final outer in outerwear.take(3)) {
            outfits.add([outer, ...outfit]);
          }
        } else {
          outfits.add(outfit);
        }
      }
    }
    
    // Generate dress outfits
    for (final dress in dresses.take(5)) {
      final outfit = [dress];
      
      // Add outerwear if needed
      if (weather.temperature < 20 && outerwear.isNotEmpty) {
        for (final outer in outerwear.take(2)) {
          outfits.add([outer, dress]);
        }
      } else {
        outfits.add(outfit);
      }
    }
    
    // Generate top + skirt combinations
    for (final top in tops.take(5)) {
      for (final skirt in skirts.take(5)) {
        final outfit = [top, skirt];
        
        if (weather.temperature < 18 && outerwear.isNotEmpty) {
          for (final outer in outerwear.take(2)) {
            outfits.add([outer, ...outfit]);
          }
        } else {
          outfits.add(outfit);
        }
      }
    }
    
    return outfits;
  }
  
  /// Calculate weather appropriateness score for an outfit
  static double _calculateWeatherScore(
    List<GarmentModel> outfit,
    WeatherCondition weather,
  ) {
    double totalScore = 0.0;
    
    for (final garment in outfit) {
      final tempScore = _getTemperatureSuitability(garment, weather.temperature);
      final conditionScore = _getConditionSuitability(garment, weather.condition);
      final seasonScore = _getSeasonalScore(garment, weather.season);
      
      final garmentScore = (tempScore * _temperatureWeight) + 
                          (conditionScore * _conditionWeight) + 
                          (seasonScore * _seasonWeight);
      
      totalScore += garmentScore;
    }
    
    // Average score across all garments
    final averageScore = totalScore / outfit.length;
    
    // Bonus for outfit cohesion
    final cohesionBonus = _calculateOutfitCohesion(outfit) * 0.1;
    
    return (averageScore + cohesionBonus).clamp(0.0, 1.0);
  }
  
  /// Calculate seasonal appropriateness score
  static double _getSeasonalScore(GarmentModel garment, Season season) {
    final tags = garment.tags.map((t) => t.toLowerCase()).toList();
    final colors = garment.colors.map((c) => c.toLowerCase()).toList();
    
    double score = 0.5; // Base score
    
    // Season-specific adjustments
    switch (season) {
      case Season.spring:
        if (tags.contains('spring') || tags.contains('light')) score += 0.3;
        if (colors.any((c) => ['pink', 'green', 'yellow', 'mint'].contains(c))) score += 0.2;
        break;
      case Season.summer:
        if (tags.contains('summer') || tags.contains('light') || tags.contains('breathable')) score += 0.3;
        if (colors.any((c) => ['white', 'yellow', 'blue', 'coral'].contains(c))) score += 0.2;
        break;
      case Season.autumn:
        if (tags.contains('autumn') || tags.contains('fall')) score += 0.3;
        if (colors.any((c) => ['brown', 'orange', 'burgundy', 'gold'].contains(c))) score += 0.2;
        break;
      case Season.winter:
        if (tags.contains('winter') || tags.contains('warm') || tags.contains('thick')) score += 0.3;
        if (colors.any((c) => ['black', 'navy', 'grey', 'burgundy'].contains(c))) score += 0.2;
        break;
    }
    
    return score.clamp(0.0, 1.0);
  }
  
  /// Calculate outfit cohesion (how well pieces work together)
  static double _calculateOutfitCohesion(List<GarmentModel> outfit) {
    if (outfit.length < 2) return 0.5;
    
    double cohesion = 0.0;
    
    // Check color harmony
    final allColors = outfit.expand((g) => g.colors).toList();
    cohesion += _calculateColorHarmony(allColors);
    
    // Check style consistency
    final allTags = outfit.expand((g) => g.tags).toList();
    cohesion += _calculateStyleConsistency(allTags);
    
    return cohesion / 2; // Average of both factors
  }
  
  /// Calculate color harmony for outfit
  static double _calculateColorHarmony(List<String> colors) {
    if (colors.length < 2) return 0.5;
    
    // Simple color harmony check
    final uniqueColors = colors.toSet().toList();
    
    // Too many colors can be overwhelming
    if (uniqueColors.length > 4) return 0.3;
    
    // Check for complementary colors
    final colorObjects = uniqueColors
        .map((name) => ColorPaletteService.getColorFromName(name))
        .where((color) => color != null)
        .cast<Color>()
        .toList();
    
    if (colorObjects.length < 2) return 0.5;
    
    // Simple harmony check based on HSL values
    final hslColors = colorObjects.map((c) => HSLColor.fromColor(c)).toList();
    
    double harmonyScore = 0.0;
    int comparisons = 0;
    
    for (int i = 0; i < hslColors.length; i++) {
      for (int j = i + 1; j < hslColors.length; j++) {
        final hue1 = hslColors[i].hue;
        final hue2 = hslColors[j].hue;
        final hueDiff = (hue1 - hue2).abs();
        
        // Good harmony: similar hues, complementary, or triadic
        if (hueDiff < 30 || (hueDiff > 150 && hueDiff < 210) || 
            (hueDiff > 100 && hueDiff < 140)) {
          harmonyScore += 0.3;
        }
        
        comparisons++;
      }
    }
    
    return comparisons > 0 ? harmonyScore / comparisons : 0.5;
  }
  
  /// Calculate style consistency
  static double _calculateStyleConsistency(List<String> tags) {
    final styleTags = tags.where((tag) => 
        ['casual', 'formal', 'sporty', 'elegant', 'trendy', 'classic', 'bohemian', 'minimalist']
            .contains(tag.toLowerCase())).toList();
    
    if (styleTags.isEmpty) return 0.5;
    
    // Check if all style tags are consistent
    final uniqueStyles = styleTags.toSet();
    
    if (uniqueStyles.length == 1) return 0.8; // Perfect consistency
    if (uniqueStyles.length == 2) return 0.6; // Good consistency
    return 0.3; // Poor consistency
  }
  
  /// Generate outfit ID
  static String _generateOutfitId(List<GarmentModel> outfit) {
    final ids = outfit.map((g) => g.id).join('_');
    return 'weather_$ids';
  }
  
  /// Generate outfit description
  static String _generateOutfitDescription(List<GarmentModel> outfit, WeatherCondition weather) {
    final temperature = weather.temperature.round();
    final condition = weather.condition.displayName;
    
    final categories = outfit.map((g) => _normalizeCategory(g.category)).toSet().toList();
    
    String description = '';
    
    if (categories.contains('outerwear')) {
      description = 'Layered look for ${temperature}°C ${condition.toLowerCase()} weather';
    } else if (categories.contains('dresses')) {
      description = 'Comfortable dress for ${temperature}°C ${condition.toLowerCase()} conditions';
    } else if (categories.contains('tops') && categories.contains('bottoms')) {
      description = 'Perfect combo for ${temperature}°C ${condition.toLowerCase()} day';
    } else {
      description = 'Weather-appropriate outfit for ${temperature}°C';
    }
    
    return description;
  }
  
  /// Generate weather-specific reason
  static String _generateWeatherReason(List<GarmentModel> outfit, WeatherCondition weather) {
    final reasons = <String>[];
    
    // Temperature-based reasons
    if (weather.temperature < 10) {
      reasons.add('Warm layers for cold weather');
    } else if (weather.temperature > 25) {
      reasons.add('Lightweight fabrics for hot weather');
    } else {
      reasons.add('Comfortable for mild temperatures');
    }
    
    // Condition-based reasons
    switch (weather.condition) {
      case WeatherType.rainy:
        if (outfit.any((g) => g.tags.contains('waterproof'))) {
          reasons.add('Water-resistant materials');
        } else {
          reasons.add('Quick-dry fabrics');
        }
        break;
      case WeatherType.sunny:
        reasons.add('Sun-friendly colors and fabrics');
        break;
      case WeatherType.windy:
        reasons.add('Secure fit for windy conditions');
        break;
      case WeatherType.snowy:
        reasons.add('Insulated for snowy weather');
        break;
      default:
        reasons.add('Versatile for changing conditions');
    }
    
    return reasons.join(' • ');
  }
  
  /// Get current weather condition (mock implementation)
  static WeatherCondition getCurrentWeather() {
    // In a real app, this would fetch from a weather API
    final now = DateTime.now();
    final season = _getCurrentSeason(now);
    
    return WeatherCondition(
      temperature: _getMockTemperature(season),
      condition: _getMockCondition(season),
      season: season,
      humidity: 60,
      windSpeed: 10,
    );
  }
  
  /// Get current season
  static Season _getCurrentSeason(DateTime date) {
    final month = date.month;
    if (month >= 3 && month <= 5) return Season.spring;
    if (month >= 6 && month <= 8) return Season.summer;
    if (month >= 9 && month <= 11) return Season.autumn;
    return Season.winter;
  }
  
  /// Get mock temperature based on season
  static double _getMockTemperature(Season season) {
    final random = math.Random();
    
    switch (season) {
      case Season.spring:
        return 15 + random.nextDouble() * 10; // 15-25°C
      case Season.summer:
        return 25 + random.nextDouble() * 10; // 25-35°C
      case Season.autumn:
        return 10 + random.nextDouble() * 10; // 10-20°C
      case Season.winter:
        return -5 + random.nextDouble() * 15; // -5-10°C
    }
  }
  
  /// Get mock weather condition
  static WeatherType _getMockCondition(Season season) {
    final conditions = [
      WeatherType.sunny,
      WeatherType.cloudy,
      WeatherType.rainy,
      WeatherType.windy,
    ];
    
    if (season == Season.winter) {
      conditions.add(WeatherType.snowy);
    }
    
    return conditions[math.Random().nextInt(conditions.length)];
  }
}

/// Weather condition data
class WeatherCondition {
  final double temperature; // in Celsius
  final WeatherType condition;
  final Season season;
  final double humidity; // percentage
  final double windSpeed; // km/h
  
  const WeatherCondition({
    required this.temperature,
    required this.condition,
    required this.season,
    required this.humidity,
    required this.windSpeed,
  });
}

/// Weather types
enum WeatherType {
  sunny,
  cloudy,
  rainy,
  snowy,
  windy,
  foggy,
}

extension WeatherTypeExtension on WeatherType {
  String get displayName {
    switch (this) {
      case WeatherType.sunny:
        return 'Sunny';
      case WeatherType.cloudy:
        return 'Cloudy';
      case WeatherType.rainy:
        return 'Rainy';
      case WeatherType.snowy:
        return 'Snowy';
      case WeatherType.windy:
        return 'Windy';
      case WeatherType.foggy:
        return 'Foggy';
    }
  }
  
  IconData get icon {
    switch (this) {
      case WeatherType.sunny:
        return Icons.wb_sunny;
      case WeatherType.cloudy:
        return Icons.cloud;
      case WeatherType.rainy:
        return Icons.beach_access;
      case WeatherType.snowy:
        return Icons.ac_unit;
      case WeatherType.windy:
        return Icons.air;
      case WeatherType.foggy:
        return Icons.cloud_queue;
    }
  }
}

/// Weather-based outfit recommendation
class WeatherOutfitRecommendation {
  final String id;
  final List<GarmentModel> garments;
  final double weatherScore;
  final double temperature;
  final WeatherType condition;
  final String description;
  final String weatherReason;
  
  const WeatherOutfitRecommendation({
    required this.id,
    required this.garments,
    required this.weatherScore,
    required this.temperature,
    required this.condition,
    required this.description,
    required this.weatherReason,
  });
}