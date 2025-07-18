import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:koutu/services/recommendation/recommendation_engine.dart';
import 'package:koutu/services/weather/weather_service.dart';
import 'package:koutu/services/auth/auth_service.dart';
import 'package:dio/dio.dart';

/// Provider for recommendation engine
final recommendationEngineProvider = Provider<RecommendationEngine>((ref) {
  final dio = ref.watch(dioProvider);
  final authService = ref.watch(authServiceProvider);
  final weatherService = ref.watch(weatherServiceProvider);
  
  return RecommendationEngine(
    dio: dio,
    authService: authService,
    weatherService: weatherService,
  );
});

/// Provider for outfit recommendations
final outfitRecommendationsProvider = FutureProvider.family<
  List<OutfitRecommendation>,
  RecommendationContext
>((ref, context) async {
  final engine = ref.watch(recommendationEngineProvider);
  final result = await engine.getOutfitRecommendations(context: context);
  
  return result.fold(
    (failure) => throw failure,
    (recommendations) => recommendations,
  );
});

/// Provider for garment pairings
final garmentPairingsProvider = FutureProvider.family<
  List<GarmentRecommendation>,
  GarmentPairingRequest
>((ref, request) async {
  final engine = ref.watch(recommendationEngineProvider);
  final result = await engine.getGarmentPairings(
    garmentId: request.garmentId,
    category: request.category,
    limit: request.limit,
  );
  
  return result.fold(
    (failure) => throw failure,
    (pairings) => pairings,
  );
});

/// Provider for style recommendations
final styleRecommendationsProvider = FutureProvider<StyleRecommendations>((ref) async {
  final engine = ref.watch(recommendationEngineProvider);
  final result = await engine.getStyleRecommendations();
  
  return result.fold(
    (failure) => throw failure,
    (recommendations) => recommendations,
  );
});

/// Provider for wardrobe analysis
final wardrobeAnalysisProvider = FutureProvider<WardrobeAnalysis>((ref) async {
  final engine = ref.watch(recommendationEngineProvider);
  final result = await engine.analyzeWardrobe();
  
  return result.fold(
    (failure) => throw failure,
    (analysis) => analysis,
  );
});

/// Provider for trending styles
final trendingStylesProvider = FutureProvider.family<
  List<TrendingStyle>,
  String?
>((ref, season) async {
  final engine = ref.watch(recommendationEngineProvider);
  final result = await engine.getTrendingStyles(season: season);
  
  return result.fold(
    (failure) => throw failure,
    (trends) => trends,
  );
});

/// Garment pairing request
class GarmentPairingRequest {
  final String garmentId;
  final String category;
  final int limit;
  
  const GarmentPairingRequest({
    required this.garmentId,
    required this.category,
    this.limit = 5,
  });
}