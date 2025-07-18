import 'package:freezed_annotation/freezed_annotation.dart';
import 'package:koutu/data/models/garment/garment_model.dart';
import 'package:koutu/data/models/outfit/outfit_model.dart';

part 'wardrobe_analytics_model.freezed.dart';
part 'wardrobe_analytics_model.g.dart';

/// Comprehensive wardrobe analytics model
@freezed
class WardrobeAnalytics with _$WardrobeAnalytics {
  const factory WardrobeAnalytics({
    required String userId,
    required String wardrobeId,
    required DateTime generatedAt,
    required OverviewMetrics overview,
    required CategoryBreakdown categoryBreakdown,
    required ColorAnalysis colorAnalysis,
    required BrandAnalysis brandAnalysis,
    required SeasonalAnalysis seasonalAnalysis,
    required UsageMetrics usageMetrics,
    required ValueMetrics valueMetrics,
    required StyleInsights styleInsights,
    required List<AnalyticsTrend> trends,
    Map<String, dynamic>? additionalMetrics,
  }) = _WardrobeAnalytics;

  factory WardrobeAnalytics.fromJson(Map<String, dynamic> json) =>
      _$WardrobeAnalyticsFromJson(json);
}

/// Overview metrics for wardrobe
@freezed
class OverviewMetrics with _$OverviewMetrics {
  const factory OverviewMetrics({
    required int totalGarments,
    required int totalOutfits,
    required int activeGarments,
    required int inactiveGarments,
    required double totalValue,
    required double averageGarmentValue,
    required int uniqueBrands,
    required int uniqueColors,
    required DateTime oldestItem,
    required DateTime newestItem,
    required double wardrobeGrowthRate,
    required int itemsAddedThisMonth,
    required int itemsRemovedThisMonth,
  }) = _OverviewMetrics;

  factory OverviewMetrics.fromJson(Map<String, dynamic> json) =>
      _$OverviewMetricsFromJson(json);
}

/// Category breakdown analysis
@freezed
class CategoryBreakdown with _$CategoryBreakdown {
  const factory CategoryBreakdown({
    required List<CategoryMetric> categories,
    required String dominantCategory,
    required Map<String, double> categoryDistribution,
    required Map<String, int> subcategoryCount,
    required List<String> missingCategories,
    required List<String> overrepresentedCategories,
  }) = _CategoryBreakdown;

  factory CategoryBreakdown.fromJson(Map<String, dynamic> json) =>
      _$CategoryBreakdownFromJson(json);
}

/// Category metric details
@freezed
class CategoryMetric with _$CategoryMetric {
  const factory CategoryMetric({
    required String category,
    required int count,
    required double percentage,
    required double totalValue,
    required double averageValue,
    required int timesWorn,
    required double wearFrequency,
    required List<String> topBrands,
    required List<String> topColors,
  }) = _CategoryMetric;

  factory CategoryMetric.fromJson(Map<String, dynamic> json) =>
      _$CategoryMetricFromJson(json);
}

/// Color analysis
@freezed
class ColorAnalysis with _$ColorAnalysis {
  const factory ColorAnalysis({
    required List<ColorMetric> colors,
    required String dominantColor,
    required List<String> colorPalette,
    required Map<String, double> colorDistribution,
    required ColorHarmony colorHarmony,
    required List<String> missingColors,
    required List<ColorCombination> popularCombinations,
  }) = _ColorAnalysis;

  factory ColorAnalysis.fromJson(Map<String, dynamic> json) =>
      _$ColorAnalysisFromJson(json);
}

/// Color metric details
@freezed
class ColorMetric with _$ColorMetric {
  const factory ColorMetric({
    required String color,
    required String hexCode,
    required int count,
    required double percentage,
    required List<String> categories,
    required int timesWorn,
    required double wearFrequency,
  }) = _ColorMetric;

  factory ColorMetric.fromJson(Map<String, dynamic> json) =>
      _$ColorMetricFromJson(json);
}

/// Color harmony analysis
@freezed
class ColorHarmony with _$ColorHarmony {
  const factory ColorHarmony({
    required double harmonyScore,
    required String harmonyType,
    required List<String> complementaryColors,
    required List<String> analogousColors,
    required List<String> triadicColors,
    required Map<String, double> seasonalAlignment,
  }) = _ColorHarmony;

  factory ColorHarmony.fromJson(Map<String, dynamic> json) =>
      _$ColorHarmonyFromJson(json);
}

/// Color combination analysis
@freezed
class ColorCombination with _$ColorCombination {
  const factory ColorCombination({
    required List<String> colors,
    required int frequency,
    required double successRate,
    required List<String> occasions,
  }) = _ColorCombination;

  factory ColorCombination.fromJson(Map<String, dynamic> json) =>
      _$ColorCombinationFromJson(json);
}

/// Brand analysis
@freezed
class BrandAnalysis with _$BrandAnalysis {
  const factory BrandAnalysis({
    required List<BrandMetric> brands,
    required String favoriteBrand,
    required Map<String, double> brandDistribution,
    required double brandLoyaltyScore,
    required List<String> emergingBrands,
    required Map<String, double> brandValueDistribution,
  }) = _BrandAnalysis;

  factory BrandAnalysis.fromJson(Map<String, dynamic> json) =>
      _$BrandAnalysisFromJson(json);
}

/// Brand metric details
@freezed
class BrandMetric with _$BrandMetric {
  const factory BrandMetric({
    required String brand,
    required int count,
    required double percentage,
    required double totalValue,
    required double averageValue,
    required List<String> categories,
    required int timesWorn,
    required double satisfactionScore,
  }) = _BrandMetric;

  factory BrandMetric.fromJson(Map<String, dynamic> json) =>
      _$BrandMetricFromJson(json);
}

/// Seasonal analysis
@freezed
class SeasonalAnalysis with _$SeasonalAnalysis {
  const factory SeasonalAnalysis({
    required Map<String, SeasonMetric> seasons,
    required String currentSeason,
    required List<String> transitionItems,
    required Map<String, List<String>> seasonalGaps,
    required double seasonalVersatilityScore,
  }) = _SeasonalAnalysis;

  factory SeasonalAnalysis.fromJson(Map<String, dynamic> json) =>
      _$SeasonalAnalysisFromJson(json);
}

/// Season metric details
@freezed
class SeasonMetric with _$SeasonMetric {
  const factory SeasonMetric({
    required String season,
    required int garmentCount,
    required int outfitCount,
    required double utilization,
    required List<String> topCategories,
    required List<String> topColors,
    required double averageTemperature,
  }) = _SeasonMetric;

  factory SeasonMetric.fromJson(Map<String, dynamic> json) =>
      _$SeasonMetricFromJson(json);
}

/// Usage metrics
@freezed
class UsageMetrics with _$UsageMetrics {
  const factory UsageMetrics({
    required double averageWearFrequency,
    required int totalWears,
    required int uniqueDaysWorn,
    required Map<String, int> wearsByDay,
    required Map<String, int> wearsByMonth,
    required List<GarmentUsage> mostWorn,
    required List<GarmentUsage> leastWorn,
    required double utilizationRate,
    required int unwornItems,
    required List<String> underutilizedCategories,
  }) = _UsageMetrics;

  factory UsageMetrics.fromJson(Map<String, dynamic> json) =>
      _$UsageMetricsFromJson(json);
}

/// Garment usage details
@freezed
class GarmentUsage with _$GarmentUsage {
  const factory GarmentUsage({
    required String garmentId,
    required String name,
    required String category,
    required int timesWorn,
    required DateTime lastWorn,
    required double wearFrequency,
    required double costPerWear,
    required List<String> commonPairings,
  }) = _GarmentUsage;

  factory GarmentUsage.fromJson(Map<String, dynamic> json) =>
      _$GarmentUsageFromJson(json);
}

/// Value metrics
@freezed
class ValueMetrics with _$ValueMetrics {
  const factory ValueMetrics({
    required double totalInvestment,
    required double currentValue,
    required double depreciationRate,
    required double averageCostPerWear,
    required Map<String, double> costPerWearByCategory,
    required List<ValueItem> bestValueItems,
    required List<ValueItem> worstValueItems,
    required double valueEfficiencyScore,
    required Map<String, double> monthlySpending,
    required double projectedAnnualSpending,
  }) = _ValueMetrics;

  factory ValueMetrics.fromJson(Map<String, dynamic> json) =>
      _$ValueMetricsFromJson(json);
}

/// Value item details
@freezed
class ValueItem with _$ValueItem {
  const factory ValueItem({
    required String garmentId,
    required String name,
    required double originalPrice,
    required double currentValue,
    required int timesWorn,
    required double costPerWear,
    required double valueScore,
    required String category,
  }) = _ValueItem;

  factory ValueItem.fromJson(Map<String, dynamic> json) =>
      _$ValueItemFromJson(json);
}

/// Style insights
@freezed
class StyleInsights with _$StyleInsights {
  const factory StyleInsights({
    required String dominantStyle,
    required List<String> stylePersonalities,
    required Map<String, double> styleDistribution,
    required double styleConsistencyScore,
    required double versatilityScore,
    required List<String> signatureColors,
    required List<String> signaturePieces,
    required List<StyleRecommendation> recommendations,
    required Map<String, double> occasionReadiness,
  }) = _StyleInsights;

  factory StyleInsights.fromJson(Map<String, dynamic> json) =>
      _$StyleInsightsFromJson(json);
}

/// Style recommendation
@freezed
class StyleRecommendation with _$StyleRecommendation {
  const factory StyleRecommendation({
    required String type,
    required String recommendation,
    required String reason,
    required double priority,
    required double potentialImpact,
    required List<String> suggestedItems,
  }) = _StyleRecommendation;

  factory StyleRecommendation.fromJson(Map<String, dynamic> json) =>
      _$StyleRecommendationFromJson(json);
}

/// Analytics trend
@freezed
class AnalyticsTrend with _$AnalyticsTrend {
  const factory AnalyticsTrend({
    required String metric,
    required String period,
    required double currentValue,
    required double previousValue,
    required double changePercentage,
    required TrendDirection direction,
    required String insight,
    required List<DataPoint> dataPoints,
  }) = _AnalyticsTrend;

  factory AnalyticsTrend.fromJson(Map<String, dynamic> json) =>
      _$AnalyticsTrendFromJson(json);
}

/// Data point for trends
@freezed
class DataPoint with _$DataPoint {
  const factory DataPoint({
    required DateTime date,
    required double value,
    String? label,
    Map<String, dynamic>? metadata,
  }) = _DataPoint;

  factory DataPoint.fromJson(Map<String, dynamic> json) =>
      _$DataPointFromJson(json);
}

/// Trend direction enum
enum TrendDirection {
  @JsonValue('up')
  up,
  @JsonValue('down')
  down,
  @JsonValue('stable')
  stable,
}

/// Outfit frequency tracking model
@freezed
class OutfitFrequencyTracking with _$OutfitFrequencyTracking {
  const factory OutfitFrequencyTracking({
    required String outfitId,
    required String name,
    required int timesWorn,
    required DateTime firstWorn,
    required DateTime lastWorn,
    required double wearFrequency,
    required List<DateTime> wearDates,
    required Map<String, int> wearsByOccasion,
    required Map<String, int> wearsBySeason,
    required double satisfactionRating,
    required List<String> garmentIds,
  }) = _OutfitFrequencyTracking;

  factory OutfitFrequencyTracking.fromJson(Map<String, dynamic> json) =>
      _$OutfitFrequencyTrackingFromJson(json);
}

/// Extensions for analytics
extension WardrobeAnalyticsExtensions on WardrobeAnalytics {
  double get overallHealthScore {
    final utilizationScore = usageMetrics.utilizationRate;
    final valueScore = valueMetrics.valueEfficiencyScore;
    final styleScore = styleInsights.styleConsistencyScore;
    final versatilityScore = styleInsights.versatilityScore;
    
    return (utilizationScore + valueScore + styleScore + versatilityScore) / 4;
  }
  
  List<String> get topInsights {
    final insights = <String>[];
    
    // Usage insights
    if (usageMetrics.unwornItems > overview.totalGarments * 0.2) {
      insights.add('${usageMetrics.unwornItems} items haven\'t been worn');
    }
    
    // Value insights
    if (valueMetrics.averageCostPerWear > 10) {
      insights.add('High cost per wear: \$${valueMetrics.averageCostPerWear.toStringAsFixed(2)}');
    }
    
    // Style insights
    if (styleInsights.versatilityScore < 0.5) {
      insights.add('Limited versatility in your wardrobe');
    }
    
    // Color insights
    if (colorAnalysis.colorHarmony.harmonyScore < 0.6) {
      insights.add('Consider improving color coordination');
    }
    
    return insights;
  }
}