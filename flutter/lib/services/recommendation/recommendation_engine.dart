import 'package:flutter/foundation.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:koutu/domain/entities/garment.dart';
import 'package:koutu/domain/entities/outfit.dart';
import 'package:koutu/domain/entities/user.dart';
import 'package:koutu/services/auth/auth_service.dart';
import 'package:koutu/services/weather/weather_service.dart';
import 'package:dartz/dartz.dart';
import 'package:dio/dio.dart';
import 'package:koutu/core/config/environment.dart';
import 'dart:convert';

/// Server-side recommendation engine for outfit suggestions
class RecommendationEngine {
  final Dio _dio;
  final AuthService _authService;
  final WeatherService _weatherService;
  
  // Cache
  final Map<String, RecommendationCache> _cache = {};
  static const Duration _cacheExpiry = Duration(hours: 2);
  
  RecommendationEngine({
    required Dio dio,
    required AuthService authService,
    required WeatherService weatherService,
  })  : _dio = dio,
        _authService = authService,
        _weatherService = weatherService;
  
  /// Get personalized outfit recommendations
  Future<Either<Failure, List<OutfitRecommendation>>> getOutfitRecommendations({
    required RecommendationContext context,
    int limit = 10,
  }) async {
    try {
      // Check cache
      final cacheKey = _getCacheKey(context);
      final cached = _getFromCache(cacheKey);
      if (cached != null) {
        return Right(cached);
      }
      
      // Get weather data if needed
      WeatherData? weather;
      if (context.considerWeather) {
        final weatherResult = await _weatherService.getCurrentWeather();
        weather = weatherResult.fold(
          (failure) => null,
          (data) => data,
        );
      }
      
      // Prepare request data
      final requestData = {
        'context': context.toJson(),
        'weather': weather?.toJson(),
        'limit': limit,
        'userId': _authService.currentUser?.id,
      };
      
      // Get auth token
      final authToken = await _authService.getAuthToken();
      
      // Call recommendation API
      final response = await _dio.post(
        '${Environment.apiUrl}/recommendations/outfits',
        data: requestData,
        options: Options(
          headers: {'Authorization': 'Bearer $authToken'},
        ),
      );
      
      if (response.statusCode == 200) {
        final recommendations = (response.data['recommendations'] as List)
            .map((json) => OutfitRecommendation.fromJson(json))
            .toList();
        
        // Cache results
        _addToCache(cacheKey, recommendations);
        
        return Right(recommendations);
      } else {
        throw Exception('Failed to get recommendations: ${response.statusCode}');
      }
    } catch (e) {
      return Left(ServerFailure('Failed to get outfit recommendations: $e'));
    }
  }
  
  /// Get garment pairing recommendations
  Future<Either<Failure, List<GarmentRecommendation>>> getGarmentPairings({
    required String garmentId,
    required String category,
    int limit = 5,
  }) async {
    try {
      final authToken = await _authService.getAuthToken();
      
      final response = await _dio.post(
        '${Environment.apiUrl}/recommendations/pairings',
        data: {
          'garmentId': garmentId,
          'category': category,
          'limit': limit,
          'userId': _authService.currentUser?.id,
        },
        options: Options(
          headers: {'Authorization': 'Bearer $authToken'},
        ),
      );
      
      if (response.statusCode == 200) {
        final recommendations = (response.data['recommendations'] as List)
            .map((json) => GarmentRecommendation.fromJson(json))
            .toList();
        
        return Right(recommendations);
      } else {
        throw Exception('Failed to get pairings: ${response.statusCode}');
      }
    } catch (e) {
      return Left(ServerFailure('Failed to get garment pairings: $e'));
    }
  }
  
  /// Get style recommendations based on user preferences
  Future<Either<Failure, StyleRecommendations>> getStyleRecommendations() async {
    try {
      final authToken = await _authService.getAuthToken();
      
      final response = await _dio.get(
        '${Environment.apiUrl}/recommendations/style',
        options: Options(
          headers: {'Authorization': 'Bearer $authToken'},
        ),
      );
      
      if (response.statusCode == 200) {
        final recommendations = StyleRecommendations.fromJson(response.data);
        return Right(recommendations);
      } else {
        throw Exception('Failed to get style recommendations: ${response.statusCode}');
      }
    } catch (e) {
      return Left(ServerFailure('Failed to get style recommendations: $e'));
    }
  }
  
  /// Get wardrobe gap analysis
  Future<Either<Failure, WardrobeAnalysis>> analyzeWardrobe() async {
    try {
      final authToken = await _authService.getAuthToken();
      
      final response = await _dio.get(
        '${Environment.apiUrl}/recommendations/wardrobe-analysis',
        options: Options(
          headers: {'Authorization': 'Bearer $authToken'},
        ),
      );
      
      if (response.statusCode == 200) {
        final analysis = WardrobeAnalysis.fromJson(response.data);
        return Right(analysis);
      } else {
        throw Exception('Failed to analyze wardrobe: ${response.statusCode}');
      }
    } catch (e) {
      return Left(ServerFailure('Failed to analyze wardrobe: $e'));
    }
  }
  
  /// Get trending styles based on user's fashion profile
  Future<Either<Failure, List<TrendingStyle>>> getTrendingStyles({
    String? season,
    int limit = 10,
  }) async {
    try {
      final authToken = await _authService.getAuthToken();
      
      final queryParams = {
        'limit': limit.toString(),
        if (season != null) 'season': season,
      };
      
      final response = await _dio.get(
        '${Environment.apiUrl}/recommendations/trending',
        queryParameters: queryParams,
        options: Options(
          headers: {'Authorization': 'Bearer $authToken'},
        ),
      );
      
      if (response.statusCode == 200) {
        final trends = (response.data['trends'] as List)
            .map((json) => TrendingStyle.fromJson(json))
            .toList();
        
        return Right(trends);
      } else {
        throw Exception('Failed to get trends: ${response.statusCode}');
      }
    } catch (e) {
      return Left(ServerFailure('Failed to get trending styles: $e'));
    }
  }
  
  /// Provide feedback on recommendations
  Future<Either<Failure, void>> provideFeedback({
    required String recommendationId,
    required RecommendationFeedback feedback,
  }) async {
    try {
      final authToken = await _authService.getAuthToken();
      
      final response = await _dio.post(
        '${Environment.apiUrl}/recommendations/feedback',
        data: {
          'recommendationId': recommendationId,
          'feedback': feedback.toJson(),
          'timestamp': DateTime.now().toIso8601String(),
        },
        options: Options(
          headers: {'Authorization': 'Bearer $authToken'},
        ),
      );
      
      if (response.statusCode == 200) {
        // Clear cache to get fresh recommendations
        _cache.clear();
        return const Right(null);
      } else {
        throw Exception('Failed to submit feedback: ${response.statusCode}');
      }
    } catch (e) {
      return Left(ServerFailure('Failed to submit feedback: $e'));
    }
  }
  
  /// Train personal style model
  Future<Either<Failure, void>> trainPersonalModel() async {
    try {
      final authToken = await _authService.getAuthToken();
      
      final response = await _dio.post(
        '${Environment.apiUrl}/recommendations/train',
        options: Options(
          headers: {'Authorization': 'Bearer $authToken'},
        ),
      );
      
      if (response.statusCode == 200) {
        // Clear cache after training
        _cache.clear();
        return const Right(null);
      } else {
        throw Exception('Failed to train model: ${response.statusCode}');
      }
    } catch (e) {
      return Left(ServerFailure('Failed to train personal model: $e'));
    }
  }
  
  // Private methods
  
  String _getCacheKey(RecommendationContext context) {
    return '${context.occasion}_${context.season}_${context.colorPreference}';
  }
  
  List<OutfitRecommendation>? _getFromCache(String key) {
    final cached = _cache[key];
    if (cached != null && !cached.isExpired) {
      return cached.recommendations;
    }
    _cache.remove(key);
    return null;
  }
  
  void _addToCache(String key, List<OutfitRecommendation> recommendations) {
    _cache[key] = RecommendationCache(
      recommendations: recommendations,
      timestamp: DateTime.now(),
    );
  }
}

/// Recommendation context for outfit suggestions
class RecommendationContext {
  final String? occasion;
  final String? season;
  final String? colorPreference;
  final bool considerWeather;
  final List<String>? excludeGarmentIds;
  final Map<String, dynamic>? preferences;
  
  const RecommendationContext({
    this.occasion,
    this.season,
    this.colorPreference,
    this.considerWeather = true,
    this.excludeGarmentIds,
    this.preferences,
  });
  
  Map<String, dynamic> toJson() => {
    if (occasion != null) 'occasion': occasion,
    if (season != null) 'season': season,
    if (colorPreference != null) 'colorPreference': colorPreference,
    'considerWeather': considerWeather,
    if (excludeGarmentIds != null) 'excludeGarmentIds': excludeGarmentIds,
    if (preferences != null) 'preferences': preferences,
  };
}

/// Outfit recommendation
class OutfitRecommendation {
  final String id;
  final String name;
  final List<String> garmentIds;
  final double confidence;
  final String reason;
  final Map<String, dynamic> metadata;
  
  const OutfitRecommendation({
    required this.id,
    required this.name,
    required this.garmentIds,
    required this.confidence,
    required this.reason,
    required this.metadata,
  });
  
  factory OutfitRecommendation.fromJson(Map<String, dynamic> json) {
    return OutfitRecommendation(
      id: json['id'],
      name: json['name'],
      garmentIds: List<String>.from(json['garmentIds']),
      confidence: json['confidence'].toDouble(),
      reason: json['reason'],
      metadata: json['metadata'] ?? {},
    );
  }
}

/// Garment recommendation
class GarmentRecommendation {
  final String garmentId;
  final String category;
  final double compatibility;
  final String reason;
  
  const GarmentRecommendation({
    required this.garmentId,
    required this.category,
    required this.compatibility,
    required this.reason,
  });
  
  factory GarmentRecommendation.fromJson(Map<String, dynamic> json) {
    return GarmentRecommendation(
      garmentId: json['garmentId'],
      category: json['category'],
      compatibility: json['compatibility'].toDouble(),
      reason: json['reason'],
    );
  }
}

/// Style recommendations
class StyleRecommendations {
  final List<String> colors;
  final List<String> patterns;
  final List<String> styles;
  final Map<String, double> colorHarmony;
  final String styleProfile;
  
  const StyleRecommendations({
    required this.colors,
    required this.patterns,
    required this.styles,
    required this.colorHarmony,
    required this.styleProfile,
  });
  
  factory StyleRecommendations.fromJson(Map<String, dynamic> json) {
    return StyleRecommendations(
      colors: List<String>.from(json['colors']),
      patterns: List<String>.from(json['patterns']),
      styles: List<String>.from(json['styles']),
      colorHarmony: Map<String, double>.from(json['colorHarmony']),
      styleProfile: json['styleProfile'],
    );
  }
}

/// Wardrobe analysis
class WardrobeAnalysis {
  final Map<String, int> categoryDistribution;
  final Map<String, int> colorDistribution;
  final List<String> missingEssentials;
  final List<String> overrepresentedCategories;
  final double versatilityScore;
  final Map<String, dynamic> recommendations;
  
  const WardrobeAnalysis({
    required this.categoryDistribution,
    required this.colorDistribution,
    required this.missingEssentials,
    required this.overrepresentedCategories,
    required this.versatilityScore,
    required this.recommendations,
  });
  
  factory WardrobeAnalysis.fromJson(Map<String, dynamic> json) {
    return WardrobeAnalysis(
      categoryDistribution: Map<String, int>.from(json['categoryDistribution']),
      colorDistribution: Map<String, int>.from(json['colorDistribution']),
      missingEssentials: List<String>.from(json['missingEssentials']),
      overrepresentedCategories: List<String>.from(json['overrepresentedCategories']),
      versatilityScore: json['versatilityScore'].toDouble(),
      recommendations: json['recommendations'],
    );
  }
}

/// Trending style
class TrendingStyle {
  final String id;
  final String name;
  final String description;
  final List<String> keyPieces;
  final List<String> colors;
  final double trendScore;
  final String imageUrl;
  
  const TrendingStyle({
    required this.id,
    required this.name,
    required this.description,
    required this.keyPieces,
    required this.colors,
    required this.trendScore,
    required this.imageUrl,
  });
  
  factory TrendingStyle.fromJson(Map<String, dynamic> json) {
    return TrendingStyle(
      id: json['id'],
      name: json['name'],
      description: json['description'],
      keyPieces: List<String>.from(json['keyPieces']),
      colors: List<String>.from(json['colors']),
      trendScore: json['trendScore'].toDouble(),
      imageUrl: json['imageUrl'],
    );
  }
}

/// Recommendation feedback
class RecommendationFeedback {
  final FeedbackType type;
  final int? rating;
  final String? comment;
  final List<String>? tags;
  
  const RecommendationFeedback({
    required this.type,
    this.rating,
    this.comment,
    this.tags,
  });
  
  Map<String, dynamic> toJson() => {
    'type': type.name,
    if (rating != null) 'rating': rating,
    if (comment != null) 'comment': comment,
    if (tags != null) 'tags': tags,
  };
}

/// Feedback type
enum FeedbackType {
  like,
  dislike,
  wear,
  skip,
  save,
}

/// Recommendation cache
class RecommendationCache {
  final List<OutfitRecommendation> recommendations;
  final DateTime timestamp;
  
  const RecommendationCache({
    required this.recommendations,
    required this.timestamp,
  });
  
  bool get isExpired => 
      DateTime.now().difference(timestamp) > RecommendationEngine._cacheExpiry;
}