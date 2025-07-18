import 'package:flutter/foundation.dart';
import 'package:koutu/data/models/analytics/wardrobe_analytics_model.dart';
import 'package:koutu/data/models/garment/garment_model.dart';
import 'package:koutu/data/models/outfit/outfit_model.dart';
import 'package:koutu/data/models/wardrobe/wardrobe_model.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:dartz/dartz.dart';

/// Service for wardrobe analytics and insights
class WardrobeAnalyticsService {
  static const String _baseUrl = 'https://api.koutu.app';
  
  /// Generate comprehensive wardrobe analytics
  static Future<Either<Failure, WardrobeAnalytics>> generateWardrobeAnalytics(
    String userId,
    String wardrobeId,
  ) async {
    try {
      await Future.delayed(const Duration(seconds: 2));
      
      final analytics = WardrobeAnalytics(
        userId: userId,
        wardrobeId: wardrobeId,
        generatedAt: DateTime.now(),
        overview: _generateOverviewMetrics(),
        categoryBreakdown: _generateCategoryBreakdown(),
        colorAnalysis: _generateColorAnalysis(),
        brandAnalysis: _generateBrandAnalysis(),
        seasonalAnalysis: _generateSeasonalAnalysis(),
        usageMetrics: _generateUsageMetrics(),
        valueMetrics: _generateValueMetrics(),
        styleInsights: _generateStyleInsights(),
        trends: _generateTrends(),
        additionalMetrics: {
          'sustainability_score': 0.75,
          'wardrobe_age_years': 3.5,
          'donation_readiness': 12,
        },
      );
      
      return Right(analytics);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Get outfit frequency tracking
  static Future<Either<Failure, List<OutfitFrequencyTracking>>> getOutfitFrequency(
    String userId,
    String wardrobeId, {
    DateTime? startDate,
    DateTime? endDate,
    int limit = 20,
  }) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      final outfits = List.generate(limit, (index) {
        final baseDate = DateTime.now().subtract(Duration(days: 180));
        final wearCount = 20 - index;
        
        return OutfitFrequencyTracking(
          outfitId: 'outfit_$index',
          name: _generateOutfitName(index),
          timesWorn: wearCount,
          firstWorn: baseDate.subtract(Duration(days: index * 10)),
          lastWorn: DateTime.now().subtract(Duration(days: index * 2)),
          wearFrequency: wearCount / 180.0,
          wearDates: _generateWearDates(wearCount, baseDate),
          wearsByOccasion: {
            'work': wearCount ~/ 2,
            'casual': wearCount ~/ 3,
            'special': wearCount ~/ 6,
          },
          wearsBySeason: {
            'spring': wearCount ~/ 4,
            'summer': wearCount ~/ 4,
            'fall': wearCount ~/ 4,
            'winter': wearCount ~/ 4,
          },
          satisfactionRating: 4.5 - (index * 0.1),
          garmentIds: List.generate(3 + (index % 3), (i) => 'garment_${index}_$i'),
        );
      });
      
      return Right(outfits);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Get style pattern analysis
  static Future<Either<Failure, Map<String, dynamic>>> getStylePatterns(
    String userId,
    String wardrobeId,
  ) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      final patterns = {
        'dominant_patterns': ['minimalist', 'casual', 'professional'],
        'color_patterns': {
          'monochrome': 0.35,
          'complementary': 0.25,
          'analogous': 0.20,
          'neutral': 0.20,
        },
        'outfit_formulas': [
          {
            'name': 'Business Casual',
            'frequency': 0.40,
            'components': ['blazer', 'shirt', 'trousers', 'loafers'],
          },
          {
            'name': 'Weekend Casual',
            'frequency': 0.30,
            'components': ['t-shirt', 'jeans', 'sneakers'],
          },
          {
            'name': 'Smart Casual',
            'frequency': 0.20,
            'components': ['sweater', 'chinos', 'boots'],
          },
          {
            'name': 'Athleisure',
            'frequency': 0.10,
            'components': ['hoodie', 'joggers', 'trainers'],
          },
        ],
        'style_evolution': {
          'past_year': ['more_casual', 'fewer_colors', 'quality_focus'],
          'emerging_trends': ['sustainable_brands', 'minimalist_aesthetic'],
        },
        'personal_uniform': {
          'exists': true,
          'description': 'Dark jeans + white shirt + blazer',
          'frequency': 0.25,
        },
      };
      
      return Right(patterns);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Get wardrobe utilization metrics
  static Future<Either<Failure, Map<String, dynamic>>> getUtilizationMetrics(
    String userId,
    String wardrobeId,
  ) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      final metrics = {
        'overall_utilization': 0.68,
        'category_utilization': {
          'tops': 0.85,
          'bottoms': 0.75,
          'outerwear': 0.45,
          'shoes': 0.60,
          'accessories': 0.40,
        },
        'utilization_by_price_range': {
          'budget': 0.90,
          'mid_range': 0.70,
          'premium': 0.45,
          'luxury': 0.30,
        },
        'dead_stock': {
          'count': 23,
          'percentage': 0.15,
          'value': 1250.00,
          'categories': ['formal_wear', 'special_occasion'],
        },
        'rotation_metrics': {
          'high_rotation': 15,
          'medium_rotation': 45,
          'low_rotation': 30,
          'no_rotation': 23,
        },
        'space_efficiency': {
          'hanging_space': 0.85,
          'shelf_space': 0.70,
          'drawer_space': 0.60,
          'overall': 0.72,
        },
      };
      
      return Right(metrics);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Get seasonal usage analytics
  static Future<Either<Failure, Map<String, dynamic>>> getSeasonalAnalytics(
    String userId,
    String wardrobeId,
  ) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      final analytics = {
        'current_season_readiness': 0.78,
        'seasonal_distribution': {
          'spring': {'items': 45, 'utilization': 0.70},
          'summer': {'items': 52, 'utilization': 0.85},
          'fall': {'items': 48, 'utilization': 0.65},
          'winter': {'items': 38, 'utilization': 0.55},
          'all_season': {'items': 67, 'utilization': 0.90},
        },
        'transition_items': [
          {'name': 'Light Jacket', 'seasons': ['spring', 'fall']},
          {'name': 'Cardigan', 'seasons': ['spring', 'fall', 'winter']},
          {'name': 'Ankle Boots', 'seasons': ['fall', 'winter', 'spring']},
        ],
        'seasonal_gaps': {
          'spring': ['rain jacket', 'light scarf'],
          'summer': ['swimwear', 'sun hat'],
          'fall': ['warm boots', 'heavy sweater'],
          'winter': ['thermal wear', 'winter coat'],
        },
        'weather_alignment': {
          'score': 0.82,
          'missing_for_current': ['waterproof shoes', 'light jacket'],
        },
      };
      
      return Right(analytics);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Get cost per wear calculations
  static Future<Either<Failure, Map<String, dynamic>>> getCostPerWear(
    String userId,
    String wardrobeId,
  ) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      final costAnalysis = {
        'average_cost_per_wear': 8.50,
        'total_wardrobe_value': 12500.00,
        'total_wears': 1470,
        'best_value_items': [
          {
            'name': 'White Oxford Shirt',
            'price': 85.00,
            'wears': 120,
            'cost_per_wear': 0.71,
          },
          {
            'name': 'Dark Wash Jeans',
            'price': 120.00,
            'wears': 156,
            'cost_per_wear': 0.77,
          },
          {
            'name': 'Black Blazer',
            'price': 250.00,
            'wears': 89,
            'cost_per_wear': 2.81,
          },
        ],
        'worst_value_items': [
          {
            'name': 'Formal Tuxedo',
            'price': 800.00,
            'wears': 2,
            'cost_per_wear': 400.00,
          },
          {
            'name': 'Designer Shoes',
            'price': 450.00,
            'wears': 5,
            'cost_per_wear': 90.00,
          },
        ],
        'cost_per_wear_by_category': {
          'everyday_basics': 2.50,
          'work_wear': 5.75,
          'casual_wear': 4.25,
          'formal_wear': 125.00,
          'activewear': 3.50,
        },
        'value_optimization_tips': [
          'Focus on versatile basics',
          'Invest in quality everyday items',
          'Rent formal wear for rare occasions',
          'Buy classic styles that last',
        ],
      };
      
      return Right(costAnalysis);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Export analytics report
  static Future<Either<Failure, String>> exportAnalyticsReport(
    String userId,
    String wardrobeId,
    String format, // 'pdf', 'csv', 'json'
  ) async {
    try {
      await Future.delayed(const Duration(seconds: 2));
      
      final reportUrl = 'https://api.koutu.app/analytics/export/${DateTime.now().millisecondsSinceEpoch}.$format';
      
      return Right(reportUrl);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Get analytics recommendations
  static Future<Either<Failure, List<Map<String, dynamic>>>> getRecommendations(
    String userId,
    String wardrobeId,
  ) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      final recommendations = [
        {
          'type': 'wardrobe_optimization',
          'priority': 'high',
          'title': 'Donate Unworn Items',
          'description': '23 items haven\'t been worn in over 6 months',
          'action': 'Review and donate',
          'impact': 'Free up 15% closet space',
        },
        {
          'type': 'style_improvement',
          'priority': 'medium',
          'title': 'Add Color Variety',
          'description': '80% of wardrobe is neutral colors',
          'action': 'Add 2-3 colorful accent pieces',
          'impact': 'Increase outfit variety by 25%',
        },
        {
          'type': 'value_optimization',
          'priority': 'medium',
          'title': 'Focus on Cost-Per-Wear',
          'description': 'Premium items have low wear frequency',
          'action': 'Prioritize versatile basics',
          'impact': 'Reduce cost-per-wear by 40%',
        },
        {
          'type': 'seasonal_preparation',
          'priority': 'low',
          'title': 'Prepare for Next Season',
          'description': 'Missing key items for upcoming weather',
          'action': 'Add waterproof jacket and boots',
          'impact': 'Improve weather readiness',
        },
      ];
      
      return Right(recommendations);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  // Helper methods for generating mock data
  static OverviewMetrics _generateOverviewMetrics() {
    return OverviewMetrics(
      totalGarments: 113,
      totalOutfits: 45,
      activeGarments: 90,
      inactiveGarments: 23,
      totalValue: 12500.00,
      averageGarmentValue: 110.62,
      uniqueBrands: 28,
      uniqueColors: 15,
      oldestItem: DateTime.now().subtract(const Duration(days: 1825)),
      newestItem: DateTime.now().subtract(const Duration(days: 7)),
      wardrobeGrowthRate: 0.05,
      itemsAddedThisMonth: 3,
      itemsRemovedThisMonth: 1,
    );
  }
  
  static CategoryBreakdown _generateCategoryBreakdown() {
    return CategoryBreakdown(
      categories: [
        CategoryMetric(
          category: 'Tops',
          count: 35,
          percentage: 0.31,
          totalValue: 2450.00,
          averageValue: 70.00,
          timesWorn: 420,
          wearFrequency: 12.0,
          topBrands: ['Uniqlo', 'COS', 'Everlane'],
          topColors: ['white', 'black', 'navy'],
        ),
        CategoryMetric(
          category: 'Bottoms',
          count: 20,
          percentage: 0.18,
          totalValue: 2200.00,
          averageValue: 110.00,
          timesWorn: 380,
          wearFrequency: 19.0,
          topBrands: ['Levi\'s', 'Everlane', 'COS'],
          topColors: ['blue', 'black', 'khaki'],
        ),
        CategoryMetric(
          category: 'Outerwear',
          count: 15,
          percentage: 0.13,
          totalValue: 3750.00,
          averageValue: 250.00,
          timesWorn: 180,
          wearFrequency: 12.0,
          topBrands: ['Patagonia', 'North Face', 'COS'],
          topColors: ['black', 'navy', 'grey'],
        ),
        CategoryMetric(
          category: 'Shoes',
          count: 18,
          percentage: 0.16,
          totalValue: 2700.00,
          averageValue: 150.00,
          timesWorn: 270,
          wearFrequency: 15.0,
          topBrands: ['Nike', 'Adidas', 'Common Projects'],
          topColors: ['white', 'black', 'brown'],
        ),
        CategoryMetric(
          category: 'Accessories',
          count: 25,
          percentage: 0.22,
          totalValue: 1400.00,
          averageValue: 56.00,
          timesWorn: 220,
          wearFrequency: 8.8,
          topBrands: ['Various', 'Fossil', 'Ray-Ban'],
          topColors: ['black', 'brown', 'silver'],
        ),
      ],
      dominantCategory: 'Tops',
      categoryDistribution: {
        'Tops': 0.31,
        'Bottoms': 0.18,
        'Outerwear': 0.13,
        'Shoes': 0.16,
        'Accessories': 0.22,
      },
      subcategoryCount: {
        'T-shirts': 15,
        'Shirts': 12,
        'Sweaters': 8,
        'Jeans': 8,
        'Trousers': 7,
        'Shorts': 5,
      },
      missingCategories: ['Swimwear', 'Formal Shoes'],
      overrepresentedCategories: ['Accessories', 'T-shirts'],
    );
  }
  
  static ColorAnalysis _generateColorAnalysis() {
    return ColorAnalysis(
      colors: [
        ColorMetric(
          color: 'Black',
          hexCode: '#000000',
          count: 28,
          percentage: 0.25,
          categories: ['Tops', 'Bottoms', 'Shoes'],
          timesWorn: 350,
          wearFrequency: 12.5,
        ),
        ColorMetric(
          color: 'White',
          hexCode: '#FFFFFF',
          count: 22,
          percentage: 0.19,
          categories: ['Tops', 'Shoes'],
          timesWorn: 280,
          wearFrequency: 12.7,
        ),
        ColorMetric(
          color: 'Navy',
          hexCode: '#000080',
          count: 18,
          percentage: 0.16,
          categories: ['Tops', 'Outerwear', 'Bottoms'],
          timesWorn: 220,
          wearFrequency: 12.2,
        ),
        ColorMetric(
          color: 'Grey',
          hexCode: '#808080',
          count: 15,
          percentage: 0.13,
          categories: ['Tops', 'Outerwear'],
          timesWorn: 180,
          wearFrequency: 12.0,
        ),
        ColorMetric(
          color: 'Blue',
          hexCode: '#0000FF',
          count: 12,
          percentage: 0.11,
          categories: ['Bottoms', 'Tops'],
          timesWorn: 160,
          wearFrequency: 13.3,
        ),
      ],
      dominantColor: 'Black',
      colorPalette: ['Black', 'White', 'Navy', 'Grey', 'Blue'],
      colorDistribution: {
        'Black': 0.25,
        'White': 0.19,
        'Navy': 0.16,
        'Grey': 0.13,
        'Blue': 0.11,
        'Others': 0.16,
      },
      colorHarmony: ColorHarmony(
        harmonyScore: 0.75,
        harmonyType: 'Monochromatic with Neutrals',
        complementaryColors: ['Orange', 'Yellow'],
        analogousColors: ['Purple', 'Green'],
        triadicColors: ['Red', 'Yellow'],
        seasonalAlignment: {
          'Spring': 0.60,
          'Summer': 0.65,
          'Fall': 0.80,
          'Winter': 0.85,
        },
      ),
      missingColors: ['Red', 'Green', 'Orange'],
      popularCombinations: [
        ColorCombination(
          colors: ['Black', 'White'],
          frequency: 45,
          successRate: 0.95,
          occasions: ['work', 'casual', 'formal'],
        ),
        ColorCombination(
          colors: ['Navy', 'White'],
          frequency: 32,
          successRate: 0.90,
          occasions: ['work', 'casual'],
        ),
        ColorCombination(
          colors: ['Grey', 'Black'],
          frequency: 28,
          successRate: 0.88,
          occasions: ['casual', 'work'],
        ),
      ],
    );
  }
  
  static BrandAnalysis _generateBrandAnalysis() {
    return BrandAnalysis(
      brands: [
        BrandMetric(
          brand: 'Uniqlo',
          count: 15,
          percentage: 0.13,
          totalValue: 750.00,
          averageValue: 50.00,
          categories: ['Tops', 'Bottoms'],
          timesWorn: 220,
          satisfactionScore: 0.88,
        ),
        BrandMetric(
          brand: 'COS',
          count: 12,
          percentage: 0.11,
          totalValue: 1440.00,
          averageValue: 120.00,
          categories: ['Tops', 'Outerwear'],
          timesWorn: 180,
          satisfactionScore: 0.92,
        ),
        BrandMetric(
          brand: 'Everlane',
          count: 10,
          percentage: 0.09,
          totalValue: 850.00,
          averageValue: 85.00,
          categories: ['Tops', 'Bottoms'],
          timesWorn: 150,
          satisfactionScore: 0.85,
        ),
      ],
      favoriteBrand: 'COS',
      brandDistribution: {
        'Uniqlo': 0.13,
        'COS': 0.11,
        'Everlane': 0.09,
        'Others': 0.67,
      },
      brandLoyaltyScore: 0.72,
      emergingBrands: ['Asket', 'Organic Basics'],
      brandValueDistribution: {
        'Budget': 0.35,
        'Mid-range': 0.45,
        'Premium': 0.15,
        'Luxury': 0.05,
      },
    );
  }
  
  static SeasonalAnalysis _generateSeasonalAnalysis() {
    return SeasonalAnalysis(
      seasons: {
        'Spring': SeasonMetric(
          season: 'Spring',
          garmentCount: 45,
          outfitCount: 18,
          utilization: 0.70,
          topCategories: ['Tops', 'Light Outerwear'],
          topColors: ['White', 'Pastel Blue', 'Grey'],
          averageTemperature: 18.0,
        ),
        'Summer': SeasonMetric(
          season: 'Summer',
          garmentCount: 52,
          outfitCount: 22,
          utilization: 0.85,
          topCategories: ['Tops', 'Shorts'],
          topColors: ['White', 'Light Blue', 'Khaki'],
          averageTemperature: 25.0,
        ),
        'Fall': SeasonMetric(
          season: 'Fall',
          garmentCount: 48,
          outfitCount: 20,
          utilization: 0.65,
          topCategories: ['Outerwear', 'Sweaters'],
          topColors: ['Brown', 'Orange', 'Grey'],
          averageTemperature: 15.0,
        ),
        'Winter': SeasonMetric(
          season: 'Winter',
          garmentCount: 38,
          outfitCount: 15,
          utilization: 0.55,
          topCategories: ['Heavy Outerwear', 'Sweaters'],
          topColors: ['Black', 'Grey', 'Navy'],
          averageTemperature: 5.0,
        ),
      },
      currentSeason: 'Fall',
      transitionItems: ['Light Jacket', 'Cardigan', 'Ankle Boots'],
      seasonalGaps: {
        'Spring': ['Rain Jacket', 'Light Scarf'],
        'Summer': ['Swimwear', 'Sun Hat'],
        'Fall': ['Warm Boots', 'Heavy Sweater'],
        'Winter': ['Thermal Wear', 'Winter Coat'],
      },
      seasonalVersatilityScore: 0.68,
    );
  }
  
  static UsageMetrics _generateUsageMetrics() {
    return UsageMetrics(
      averageWearFrequency: 13.0,
      totalWears: 1470,
      uniqueDaysWorn: 280,
      wearsByDay: {
        'Monday': 210,
        'Tuesday': 215,
        'Wednesday': 220,
        'Thursday': 218,
        'Friday': 225,
        'Saturday': 195,
        'Sunday': 187,
      },
      wearsByMonth: {
        'January': 110,
        'February': 105,
        'March': 120,
        'April': 125,
        'May': 130,
        'June': 135,
        'July': 140,
        'August': 138,
        'September': 125,
        'October': 120,
        'November': 115,
        'December': 107,
      },
      mostWorn: [
        GarmentUsage(
          garmentId: 'garment_1',
          name: 'White Oxford Shirt',
          category: 'Tops',
          timesWorn: 120,
          lastWorn: DateTime.now().subtract(const Duration(days: 2)),
          wearFrequency: 0.67,
          costPerWear: 0.71,
          commonPairings: ['Dark Jeans', 'Navy Chinos', 'Black Blazer'],
        ),
        GarmentUsage(
          garmentId: 'garment_2',
          name: 'Dark Wash Jeans',
          category: 'Bottoms',
          timesWorn: 156,
          lastWorn: DateTime.now().subtract(const Duration(days: 1)),
          wearFrequency: 0.87,
          costPerWear: 0.77,
          commonPairings: ['White Shirt', 'Black T-shirt', 'Grey Sweater'],
        ),
      ],
      leastWorn: [
        GarmentUsage(
          garmentId: 'garment_98',
          name: 'Formal Tuxedo',
          category: 'Formal',
          timesWorn: 2,
          lastWorn: DateTime.now().subtract(const Duration(days: 365)),
          wearFrequency: 0.01,
          costPerWear: 400.00,
          commonPairings: ['Dress Shoes', 'Bow Tie'],
        ),
      ],
      utilizationRate: 0.68,
      unwornItems: 23,
      underutilizedCategories: ['Formal Wear', 'Special Occasion'],
    );
  }
  
  static ValueMetrics _generateValueMetrics() {
    return ValueMetrics(
      totalInvestment: 12500.00,
      currentValue: 8750.00,
      depreciationRate: 0.30,
      averageCostPerWear: 8.50,
      costPerWearByCategory: {
        'Everyday Basics': 2.50,
        'Work Wear': 5.75,
        'Casual Wear': 4.25,
        'Formal Wear': 125.00,
        'Activewear': 3.50,
      },
      bestValueItems: [
        ValueItem(
          garmentId: 'garment_1',
          name: 'White Oxford Shirt',
          originalPrice: 85.00,
          currentValue: 60.00,
          timesWorn: 120,
          costPerWear: 0.71,
          valueScore: 0.95,
          category: 'Tops',
        ),
        ValueItem(
          garmentId: 'garment_2',
          name: 'Dark Wash Jeans',
          originalPrice: 120.00,
          currentValue: 85.00,
          timesWorn: 156,
          costPerWear: 0.77,
          valueScore: 0.93,
          category: 'Bottoms',
        ),
      ],
      worstValueItems: [
        ValueItem(
          garmentId: 'garment_98',
          name: 'Formal Tuxedo',
          originalPrice: 800.00,
          currentValue: 400.00,
          timesWorn: 2,
          costPerWear: 400.00,
          valueScore: 0.05,
          category: 'Formal',
        ),
      ],
      valueEfficiencyScore: 0.72,
      monthlySpending: {
        'January': 150.00,
        'February': 0.00,
        'March': 250.00,
        'April': 180.00,
        'May': 0.00,
        'June': 320.00,
        'July': 150.00,
        'August': 0.00,
        'September': 450.00,
        'October': 280.00,
        'November': 200.00,
        'December': 350.00,
      },
      projectedAnnualSpending: 2330.00,
    );
  }
  
  static StyleInsights _generateStyleInsights() {
    return StyleInsights(
      dominantStyle: 'Minimalist Professional',
      stylePersonalities: ['Minimalist', 'Classic', 'Professional'],
      styleDistribution: {
        'Minimalist': 0.40,
        'Classic': 0.30,
        'Professional': 0.20,
        'Casual': 0.10,
      },
      styleConsistencyScore: 0.82,
      versatilityScore: 0.75,
      signatureColors: ['Black', 'White', 'Navy'],
      signaturePieces: ['White Shirt', 'Dark Jeans', 'Black Blazer'],
      recommendations: [
        StyleRecommendation(
          type: 'color_variety',
          recommendation: 'Add 2-3 colorful accent pieces',
          reason: '80% of wardrobe is neutral colors',
          priority: 0.8,
          potentialImpact: 0.25,
          suggestedItems: ['Burgundy Sweater', 'Forest Green Shirt', 'Mustard Scarf'],
        ),
        StyleRecommendation(
          type: 'style_expansion',
          recommendation: 'Explore smart casual options',
          reason: 'Limited casual Friday options',
          priority: 0.6,
          potentialImpact: 0.15,
          suggestedItems: ['Knit Polo', 'Casual Blazer', 'Loafers'],
        ),
      ],
      occasionReadiness: {
        'Work': 0.90,
        'Casual': 0.75,
        'Formal': 0.40,
        'Athletic': 0.60,
        'Social': 0.70,
      },
    );
  }
  
  static List<AnalyticsTrend> _generateTrends() {
    return [
      AnalyticsTrend(
        metric: 'Wardrobe Size',
        period: 'Last 6 Months',
        currentValue: 113.0,
        previousValue: 105.0,
        changePercentage: 7.6,
        direction: TrendDirection.up,
        insight: 'Steady growth with focus on quality basics',
        dataPoints: _generateDataPoints(6, 105, 113),
      ),
      AnalyticsTrend(
        metric: 'Cost Per Wear',
        period: 'Last 3 Months',
        currentValue: 8.50,
        previousValue: 12.30,
        changePercentage: -30.9,
        direction: TrendDirection.down,
        insight: 'Improved value through better utilization',
        dataPoints: _generateDataPoints(3, 12.30, 8.50),
      ),
      AnalyticsTrend(
        metric: 'Color Diversity',
        period: 'Last Year',
        currentValue: 15.0,
        previousValue: 12.0,
        changePercentage: 25.0,
        direction: TrendDirection.up,
        insight: 'Gradual expansion beyond neutrals',
        dataPoints: _generateDataPoints(12, 12, 15),
      ),
    ];
  }
  
  static List<DataPoint> _generateDataPoints(int count, double startValue, double endValue) {
    final points = <DataPoint>[];
    final increment = (endValue - startValue) / (count - 1);
    
    for (int i = 0; i < count; i++) {
      points.add(DataPoint(
        date: DateTime.now().subtract(Duration(days: (count - i - 1) * 30)),
        value: startValue + (increment * i),
      ));
    }
    
    return points;
  }
  
  static List<DateTime> _generateWearDates(int count, DateTime baseDate) {
    final dates = <DateTime>[];
    final interval = 180 ~/ count;
    
    for (int i = 0; i < count; i++) {
      dates.add(baseDate.add(Duration(days: i * interval)));
    }
    
    return dates;
  }
  
  static String _generateOutfitName(int index) {
    final names = [
      'Business Casual Monday',
      'Weekend Brunch Look',
      'Date Night Special',
      'Casual Friday Style',
      'Meeting Ready',
      'Travel Comfort',
      'Evening Elegant',
      'Gym to Coffee',
      'Smart Casual',
      'Minimalist Chic',
    ];
    
    return names[index % names.length];
  }
}