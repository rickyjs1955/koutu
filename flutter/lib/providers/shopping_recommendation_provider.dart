import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:koutu/services/notification/shopping_recommendation_service.dart';
import 'package:koutu/services/notification/push_notification_service.dart';
import 'package:koutu/services/recommendation/recommendation_engine.dart';
import 'package:koutu/services/analytics/analytics_service.dart';
import 'package:koutu/data/datasources/local/database/app_database.dart';

/// Provider for shopping recommendation service
final shoppingRecommendationServiceProvider = Provider<ShoppingRecommendationService>((ref) {
  final notificationService = ref.watch(pushNotificationServiceProvider);
  final recommendationEngine = ref.watch(recommendationEngineProvider);
  final analyticsService = ref.watch(analyticsServiceProvider);
  final database = ref.watch(databaseProvider);
  
  final shoppingService = ShoppingRecommendationService(
    notificationService: notificationService,
    recommendationEngine: recommendationEngine,
    analyticsService: analyticsService,
    database: database,
  );
  
  // Initialize on creation
  shoppingService.initialize();
  
  // Dispose when provider is destroyed
  ref.onDispose(() {
    shoppingService.dispose();
  });
  
  return shoppingService;
});

/// Provider for wardrobe analysis
final wardrobeAnalysisProvider = FutureProvider.autoDispose<WardrobeAnalysis>((ref) async {
  final service = ref.watch(shoppingRecommendationServiceProvider);
  final result = await service.analyzeWardrobe();
  
  return result.fold(
    (failure) => throw failure,
    (analysis) => analysis,
  );
});

/// Provider for shopping recommendations
final shoppingRecommendationsProvider = FutureProvider.family<
  List<ShoppingRecommendation>,
  ShoppingRecommendationParams
>((ref, params) async {
  final service = ref.watch(shoppingRecommendationServiceProvider);
  final result = await service.getRecommendations(
    category: params.category,
    priceRange: params.priceRange,
    occasion: params.occasion,
    limit: params.limit,
  );
  
  return result.fold(
    (failure) => throw failure,
    (recommendations) => recommendations,
  );
});

/// Provider for shopping deals
final shoppingDealsProvider = FutureProvider<List<ShoppingDeal>>((ref) async {
  final service = ref.watch(shoppingRecommendationServiceProvider);
  final result = await service.checkForDeals();
  
  return result.fold(
    (failure) => throw failure,
    (deals) => deals,
  );
});

/// Provider for shopping recommendation settings
final shoppingRecommendationSettingsProvider = Provider<ShoppingRecommendationSettings>((ref) {
  final service = ref.watch(shoppingRecommendationServiceProvider);
  return service.getSettings();
});

/// Parameters for shopping recommendations
class ShoppingRecommendationParams {
  final ShoppingCategory? category;
  final PriceRange? priceRange;
  final String? occasion;
  final int limit;
  
  const ShoppingRecommendationParams({
    this.category,
    this.priceRange,
    this.occasion,
    this.limit = 10,
  });
  
  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is ShoppingRecommendationParams &&
          runtimeType == other.runtimeType &&
          category == other.category &&
          priceRange == other.priceRange &&
          occasion == other.occasion &&
          limit == other.limit;
  
  @override
  int get hashCode =>
      category.hashCode ^
      priceRange.hashCode ^
      occasion.hashCode ^
      limit.hashCode;
}