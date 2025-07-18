import 'package:flutter/foundation.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:koutu/data/models/garment/garment_model.dart';
import 'package:koutu/data/models/outfit/outfit_model.dart';
import 'package:koutu/services/cache/image_cache_service.dart';
import 'package:koutu/services/performance/lazy_loading_service.dart';
import 'package:dartz/dartz.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'dart:convert';
import 'dart:math' as math;

/// Service for predictive content preloading based on user behavior
class PredictivePreloader {
  static const String _prefsKeyUsagePattern = 'usage_pattern';
  static const String _prefsKeyViewHistory = 'view_history';
  static const String _prefsKeyPredictions = 'content_predictions';
  
  // Singleton instance
  static final PredictivePreloader _instance = PredictivePreloader._internal();
  factory PredictivePreloader() => _instance;
  PredictivePreloader._internal();
  
  // User behavior tracking
  final Map<String, UserAction> _recentActions = {};
  final Map<String, int> _contentAccessCount = {};
  final Map<String, DateTime> _lastAccessTime = {};
  final Map<String, List<String>> _navigationPatterns = {};
  
  // Prediction models
  final Map<String, double> _contentProbabilities = {};
  final Map<String, List<String>> _relatedContent = {};
  
  // Services
  final ImageCacheService _imageCacheService = ImageCacheService();
  
  /// Initialize the predictive preloader
  Future<void> initialize() async {
    await _loadUserPatterns();
    await _analyzePatterns();
  }
  
  /// Track user action for pattern learning
  void trackAction(UserAction action) {
    _recentActions[action.id] = action;
    
    // Update access count
    _contentAccessCount[action.contentId] = 
        (_contentAccessCount[action.contentId] ?? 0) + 1;
    
    // Update last access time
    _lastAccessTime[action.contentId] = action.timestamp;
    
    // Track navigation patterns
    if (action.previousContentId != null) {
      _navigationPatterns[action.previousContentId!] ??= [];
      _navigationPatterns[action.previousContentId!]!.add(action.contentId);
    }
    
    // Trigger pattern analysis periodically
    if (_recentActions.length % 10 == 0) {
      _analyzePatterns();
    }
    
    // Save patterns periodically
    if (_recentActions.length % 50 == 0) {
      _saveUserPatterns();
    }
  }
  
  /// Predict next content based on current context
  Future<List<PredictedContent>> predictNextContent({
    required String currentContentId,
    required ContentType contentType,
    Map<String, dynamic>? context,
  }) async {
    final predictions = <PredictedContent>[];
    
    // 1. Navigation-based predictions
    if (_navigationPatterns.containsKey(currentContentId)) {
      final nextItems = _navigationPatterns[currentContentId]!;
      final itemCounts = <String, int>{};
      
      for (final item in nextItems) {
        itemCounts[item] = (itemCounts[item] ?? 0) + 1;
      }
      
      final sortedItems = itemCounts.entries.toList()
        ..sort((a, b) => b.value.compareTo(a.value));
      
      for (final entry in sortedItems.take(5)) {
        predictions.add(PredictedContent(
          contentId: entry.key,
          contentType: contentType,
          probability: entry.value / nextItems.length,
          reason: PredictionReason.navigationPattern,
        ));
      }
    }
    
    // 2. Time-based predictions
    final currentHour = DateTime.now().hour;
    final timeBasedContent = await _getTimeBasedPredictions(currentHour, contentType);
    predictions.addAll(timeBasedContent);
    
    // 3. Frequency-based predictions
    final frequentContent = _getFrequentlyAccessedContent(contentType);
    predictions.addAll(frequentContent);
    
    // 4. Related content predictions
    if (_relatedContent.containsKey(currentContentId)) {
      for (final relatedId in _relatedContent[currentContentId]!.take(3)) {
        predictions.add(PredictedContent(
          contentId: relatedId,
          contentType: contentType,
          probability: 0.6,
          reason: PredictionReason.relatedContent,
        ));
      }
    }
    
    // 5. Context-based predictions (e.g., weather, season)
    if (context != null) {
      final contextualPredictions = _getContextualPredictions(context, contentType);
      predictions.addAll(contextualPredictions);
    }
    
    // Sort by probability and remove duplicates
    final uniquePredictions = <String, PredictedContent>{};
    for (final prediction in predictions) {
      if (!uniquePredictions.containsKey(prediction.contentId)) {
        uniquePredictions[prediction.contentId] = prediction;
      } else {
        // Keep the one with higher probability
        final existing = uniquePredictions[prediction.contentId]!;
        if (prediction.probability > existing.probability) {
          uniquePredictions[prediction.contentId] = prediction;
        }
      }
    }
    
    final sortedPredictions = uniquePredictions.values.toList()
      ..sort((a, b) => b.probability.compareTo(a.probability));
    
    return sortedPredictions.take(10).toList();
  }
  
  /// Preload content based on predictions
  Future<void> preloadPredictedContent(
    List<PredictedContent> predictions,
  ) async {
    // Group by content type for efficient loading
    final garmentIds = <String>[];
    final outfitIds = <String>[];
    final imageUrls = <String>[];
    
    for (final prediction in predictions) {
      if (prediction.probability < 0.3) continue; // Skip low probability
      
      switch (prediction.contentType) {
        case ContentType.garment:
          garmentIds.add(prediction.contentId);
          break;
        case ContentType.outfit:
          outfitIds.add(prediction.contentId);
          break;
        case ContentType.image:
          imageUrls.add(prediction.contentId);
          break;
        default:
          break;
      }
    }
    
    // Preload in parallel
    await Future.wait([
      if (garmentIds.isNotEmpty) _preloadGarments(garmentIds),
      if (outfitIds.isNotEmpty) _preloadOutfits(outfitIds),
      if (imageUrls.isNotEmpty) _preloadImages(imageUrls),
    ]);
  }
  
  /// Analyze user behavior patterns
  Future<void> _analyzePatterns() async {
    // Analyze access frequency patterns
    _analyzeAccessFrequency();
    
    // Analyze time-based patterns
    _analyzeTimePatterns();
    
    // Analyze navigation sequences
    _analyzeNavigationSequences();
    
    // Update content relationships
    _updateContentRelationships();
    
    // Clean old data
    _cleanOldData();
  }
  
  void _analyzeAccessFrequency() {
    // Calculate content access probabilities
    final totalAccesses = _contentAccessCount.values.fold(0, (a, b) => a + b);
    
    if (totalAccesses > 0) {
      _contentAccessCount.forEach((contentId, count) {
        _contentProbabilities[contentId] = count / totalAccesses;
      });
    }
  }
  
  void _analyzeTimePatterns() {
    // Group actions by hour of day
    final hourlyPatterns = <int, List<String>>{};
    
    _recentActions.forEach((id, action) {
      final hour = action.timestamp.hour;
      hourlyPatterns[hour] ??= [];
      hourlyPatterns[hour]!.add(action.contentId);
    });
    
    // Store patterns for time-based predictions
    // This would be more sophisticated in a real implementation
  }
  
  void _analyzeNavigationSequences() {
    // Find common navigation sequences using simple frequency analysis
    final sequences = <String, int>{};
    
    _navigationPatterns.forEach((from, toList) {
      for (final to in toList) {
        final sequence = '$from->$to';
        sequences[sequence] = (sequences[sequence] ?? 0) + 1;
      }
    });
    
    // Could implement more sophisticated sequence mining algorithms
  }
  
  void _updateContentRelationships() {
    // Build content relationships based on co-access patterns
    final coAccessMatrix = <String, Map<String, int>>{};
    
    // Simple implementation: items accessed in the same session are related
    final sessions = _groupActionsIntoSessions();
    
    for (final session in sessions) {
      for (int i = 0; i < session.length; i++) {
        for (int j = i + 1; j < session.length && j < i + 5; j++) {
          final contentA = session[i].contentId;
          final contentB = session[j].contentId;
          
          coAccessMatrix[contentA] ??= {};
          coAccessMatrix[contentA]![contentB] = 
              (coAccessMatrix[contentA]![contentB] ?? 0) + 1;
          
          coAccessMatrix[contentB] ??= {};
          coAccessMatrix[contentB]![contentA] = 
              (coAccessMatrix[contentB]![contentA] ?? 0) + 1;
        }
      }
    }
    
    // Convert to related content list
    coAccessMatrix.forEach((contentId, related) {
      final sortedRelated = related.entries.toList()
        ..sort((a, b) => b.value.compareTo(a.value));
      
      _relatedContent[contentId] = sortedRelated
          .take(10)
          .map((e) => e.key)
          .toList();
    });
  }
  
  List<List<UserAction>> _groupActionsIntoSessions() {
    final sessions = <List<UserAction>>[];
    final sortedActions = _recentActions.values.toList()
      ..sort((a, b) => a.timestamp.compareTo(b.timestamp));
    
    List<UserAction> currentSession = [];
    DateTime? lastActionTime;
    
    for (final action in sortedActions) {
      if (lastActionTime != null && 
          action.timestamp.difference(lastActionTime).inMinutes > 30) {
        // New session if more than 30 minutes gap
        if (currentSession.isNotEmpty) {
          sessions.add(currentSession);
          currentSession = [];
        }
      }
      
      currentSession.add(action);
      lastActionTime = action.timestamp;
    }
    
    if (currentSession.isNotEmpty) {
      sessions.add(currentSession);
    }
    
    return sessions;
  }
  
  void _cleanOldData() {
    // Remove actions older than 30 days
    final cutoffDate = DateTime.now().subtract(const Duration(days: 30));
    
    _recentActions.removeWhere((id, action) => 
        action.timestamp.isBefore(cutoffDate));
    
    // Remove content not accessed in 60 days
    final accessCutoff = DateTime.now().subtract(const Duration(days: 60));
    
    _lastAccessTime.removeWhere((contentId, lastAccess) => 
        lastAccess.isBefore(accessCutoff));
  }
  
  Future<List<PredictedContent>> _getTimeBasedPredictions(
    int hour,
    ContentType contentType,
  ) async {
    // Simple time-based predictions
    // In reality, this would use learned patterns
    final predictions = <PredictedContent>[];
    
    // Morning: casual/work outfits
    if (hour >= 6 && hour <= 9) {
      predictions.add(PredictedContent(
        contentId: 'morning_outfit',
        contentType: contentType,
        probability: 0.7,
        reason: PredictionReason.timeBased,
      ));
    }
    
    // Evening: social/dinner outfits
    if (hour >= 18 && hour <= 21) {
      predictions.add(PredictedContent(
        contentId: 'evening_outfit',
        contentType: contentType,
        probability: 0.6,
        reason: PredictionReason.timeBased,
      ));
    }
    
    return predictions;
  }
  
  List<PredictedContent> _getFrequentlyAccessedContent(
    ContentType contentType,
  ) {
    final predictions = <PredictedContent>[];
    
    final sortedContent = _contentAccessCount.entries.toList()
      ..sort((a, b) => b.value.compareTo(a.value));
    
    for (final entry in sortedContent.take(5)) {
      predictions.add(PredictedContent(
        contentId: entry.key,
        contentType: contentType,
        probability: _contentProbabilities[entry.key] ?? 0.5,
        reason: PredictionReason.frequency,
      ));
    }
    
    return predictions;
  }
  
  List<PredictedContent> _getContextualPredictions(
    Map<String, dynamic> context,
    ContentType contentType,
  ) {
    final predictions = <PredictedContent>[];
    
    // Weather-based predictions
    if (context['weather'] != null) {
      final weather = context['weather'] as String;
      
      if (weather == 'rainy') {
        predictions.add(PredictedContent(
          contentId: 'raincoat',
          contentType: contentType,
          probability: 0.8,
          reason: PredictionReason.contextual,
        ));
      } else if (weather == 'sunny') {
        predictions.add(PredictedContent(
          contentId: 'summer_outfit',
          contentType: contentType,
          probability: 0.7,
          reason: PredictionReason.contextual,
        ));
      }
    }
    
    // Season-based predictions
    if (context['season'] != null) {
      final season = context['season'] as String;
      
      predictions.add(PredictedContent(
        contentId: '${season}_collection',
        contentType: contentType,
        probability: 0.6,
        reason: PredictionReason.contextual,
      ));
    }
    
    return predictions;
  }
  
  Future<void> _preloadGarments(List<String> garmentIds) async {
    // Preload garment data and images
    await LazyLoadingService.preloadPages<GarmentModel>(
      cacheKey: 'predicted_garments',
      pages: [0],
      pageSize: garmentIds.length,
      loader: (page, size) async {
        // In real implementation, this would load from repository
        return [];
      },
    );
  }
  
  Future<void> _preloadOutfits(List<String> outfitIds) async {
    // Similar to garments
    await LazyLoadingService.preloadPages<OutfitModel>(
      cacheKey: 'predicted_outfits',
      pages: [0],
      pageSize: outfitIds.length,
      loader: (page, size) async {
        return [];
      },
    );
  }
  
  Future<void> _preloadImages(List<String> imageUrls) async {
    await _imageCacheService.preloadImages(
      imageUrls,
      strategy: ImageCacheStrategy.balanced,
    );
  }
  
  Future<void> _loadUserPatterns() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      
      // Load usage patterns
      final patternJson = prefs.getString(_prefsKeyUsagePattern);
      if (patternJson != null) {
        final patterns = json.decode(patternJson) as Map<String, dynamic>;
        patterns.forEach((key, value) {
          _contentAccessCount[key] = value as int;
        });
      }
      
      // Load view history
      final historyJson = prefs.getString(_prefsKeyViewHistory);
      if (historyJson != null) {
        final history = json.decode(historyJson) as List<dynamic>;
        for (final item in history) {
          final action = UserAction.fromJson(item);
          _recentActions[action.id] = action;
        }
      }
    } catch (e) {
      debugPrint('Error loading user patterns: $e');
    }
  }
  
  Future<void> _saveUserPatterns() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      
      // Save usage patterns
      await prefs.setString(
        _prefsKeyUsagePattern,
        json.encode(_contentAccessCount),
      );
      
      // Save recent history (last 100 actions)
      final recentActionsList = _recentActions.values.toList()
        ..sort((a, b) => b.timestamp.compareTo(a.timestamp));
      
      final historyToSave = recentActionsList
          .take(100)
          .map((a) => a.toJson())
          .toList();
      
      await prefs.setString(
        _prefsKeyViewHistory,
        json.encode(historyToSave),
      );
    } catch (e) {
      debugPrint('Error saving user patterns: $e');
    }
  }
}

/// User action model
class UserAction {
  final String id;
  final String contentId;
  final ContentType contentType;
  final ActionType actionType;
  final DateTime timestamp;
  final String? previousContentId;
  final Map<String, dynamic>? metadata;
  
  UserAction({
    String? id,
    required this.contentId,
    required this.contentType,
    required this.actionType,
    DateTime? timestamp,
    this.previousContentId,
    this.metadata,
  }) : id = id ?? '${contentId}_${DateTime.now().millisecondsSinceEpoch}',
       timestamp = timestamp ?? DateTime.now();
  
  Map<String, dynamic> toJson() => {
    'id': id,
    'contentId': contentId,
    'contentType': contentType.index,
    'actionType': actionType.index,
    'timestamp': timestamp.toIso8601String(),
    'previousContentId': previousContentId,
    'metadata': metadata,
  };
  
  factory UserAction.fromJson(Map<String, dynamic> json) => UserAction(
    id: json['id'],
    contentId: json['contentId'],
    contentType: ContentType.values[json['contentType']],
    actionType: ActionType.values[json['actionType']],
    timestamp: DateTime.parse(json['timestamp']),
    previousContentId: json['previousContentId'],
    metadata: json['metadata'],
  );
}

/// Predicted content model
class PredictedContent {
  final String contentId;
  final ContentType contentType;
  final double probability;
  final PredictionReason reason;
  
  const PredictedContent({
    required this.contentId,
    required this.contentType,
    required this.probability,
    required this.reason,
  });
}

/// Content types
enum ContentType {
  garment,
  outfit,
  wardrobe,
  image,
  category,
}

/// Action types
enum ActionType {
  view,
  tap,
  scroll,
  search,
  filter,
  share,
  favorite,
}

/// Prediction reasons
enum PredictionReason {
  navigationPattern,
  timeBased,
  frequency,
  relatedContent,
  contextual,
  trending,
}