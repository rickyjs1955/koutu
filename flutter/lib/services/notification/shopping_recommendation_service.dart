import 'package:flutter/material.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:koutu/services/notification/push_notification_service.dart';
import 'package:koutu/services/recommendation/recommendation_engine.dart';
import 'package:koutu/services/analytics/analytics_service.dart';
import 'package:koutu/data/datasources/local/database/app_database.dart';
import 'package:dartz/dartz.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'dart:async';
import 'dart:convert';

/// Service for smart shopping recommendations
class ShoppingRecommendationService {
  final PushNotificationService _notificationService;
  final RecommendationEngine _recommendationEngine;
  final AnalyticsService _analyticsService;
  final AppDatabase _database;
  
  // Settings
  ShoppingRecommendationSettings _settings = const ShoppingRecommendationSettings();
  
  // Recommendation tracking
  final Map<String, ShoppingRecommendation> _activeRecommendations = {};
  final Map<String, DateTime> _lastAnalysisTime = {};
  final Map<String, List<WardrobeGap>> _wardrobeGaps = {};
  
  // Timers
  Timer? _analysisTimer;
  Timer? _dealCheckTimer;
  
  // Constants
  static const Duration _analysisInterval = Duration(days: 7);
  static const Duration _dealCheckInterval = Duration(hours: 6);
  
  ShoppingRecommendationService({
    required PushNotificationService notificationService,
    required RecommendationEngine recommendationEngine,
    required AnalyticsService analyticsService,
    required AppDatabase database,
  })  : _notificationService = notificationService,
        _recommendationEngine = recommendationEngine,
        _analyticsService = analyticsService,
        _database = database;
  
  /// Initialize shopping recommendation service
  Future<void> initialize() async {
    await _loadSettings();
    await _loadActiveRecommendations();
    
    if (_settings.enabled) {
      _startRecommendationEngine();
    }
  }
  
  /// Analyze wardrobe and generate recommendations
  Future<Either<Failure, WardrobeAnalysis>> analyzeWardrobe({
    bool forceRefresh = false,
  }) async {
    try {
      final userId = 'current_user'; // Get from auth service
      
      // Check if we need to refresh
      final lastAnalysis = _lastAnalysisTime[userId];
      if (!forceRefresh && 
          lastAnalysis != null &&
          DateTime.now().difference(lastAnalysis) < _analysisInterval) {
        // Return cached analysis
        return Right(_getCachedAnalysis(userId));
      }
      
      // Get all garments
      final garments = await _database.select(_database.garments).get();
      
      // Analyze wardrobe composition
      final categoryCount = <String, int>{};
      final colorCount = <String, int>{};
      final brandCount = <String, int>{};
      final seasonalCoverage = <String, int>{};
      
      for (final garment in garments) {
        // Count categories
        final category = garment.category ?? 'Other';
        categoryCount[category] = (categoryCount[category] ?? 0) + 1;
        
        // Count colors
        final color = garment.color ?? 'Unknown';
        colorCount[color] = (colorCount[color] ?? 0) + 1;
        
        // Count brands
        final brand = garment.brand ?? 'Unknown';
        brandCount[brand] = (brandCount[brand] ?? 0) + 1;
        
        // Count seasonal coverage
        final seasons = garment.seasons?.split(',') ?? [];
        for (final season in seasons) {
          seasonalCoverage[season.trim()] = 
              (seasonalCoverage[season.trim()] ?? 0) + 1;
        }
      }
      
      // Identify gaps
      final gaps = _identifyWardrobeGaps(
        garments: garments,
        categoryCount: categoryCount,
        colorCount: colorCount,
        seasonalCoverage: seasonalCoverage,
      );
      
      // Generate recommendations
      final recommendations = await _generateRecommendations(gaps);
      
      // Create analysis result
      final analysis = WardrobeAnalysis(
        totalGarments: garments.length,
        categoryDistribution: categoryCount,
        colorDistribution: colorCount,
        brandDistribution: brandCount,
        seasonalCoverage: seasonalCoverage,
        gaps: gaps,
        recommendations: recommendations,
        analyzedAt: DateTime.now(),
      );
      
      // Cache results
      _lastAnalysisTime[userId] = DateTime.now();
      _wardrobeGaps[userId] = gaps;
      
      // Track analytics
      await _analyticsService.trackEvent(
        eventType: 'wardrobe_analysis',
        eventName: 'analyze_wardrobe',
        properties: {
          'totalGarments': garments.length,
          'gapsFound': gaps.length,
          'recommendationsGenerated': recommendations.length,
        },
      );
      
      return Right(analysis);
    } catch (e) {
      return Left(DatabaseFailure('Failed to analyze wardrobe: $e'));
    }
  }
  
  /// Get personalized shopping recommendations
  Future<Either<Failure, List<ShoppingRecommendation>>> getRecommendations({
    ShoppingCategory? category,
    PriceRange? priceRange,
    String? occasion,
    int limit = 10,
  }) async {
    try {
      // Get wardrobe analysis
      final analysisResult = await analyzeWardrobe();
      if (analysisResult.isLeft()) {
        return Left(analysisResult.fold((l) => l, (r) => throw Exception()));
      }
      
      final analysis = analysisResult.getOrElse(() => throw Exception());
      
      // Filter recommendations
      var recommendations = analysis.recommendations;
      
      if (category != null) {
        recommendations = recommendations
            .where((r) => r.category == category)
            .toList();
      }
      
      if (priceRange != null) {
        recommendations = recommendations
            .where((r) => r.priceRange == priceRange)
            .toList();
      }
      
      if (occasion != null) {
        recommendations = recommendations
            .where((r) => r.occasions.contains(occasion))
            .toList();
      }
      
      // Sort by priority
      recommendations.sort((a, b) => b.priority.compareTo(a.priority));
      
      // Limit results
      if (recommendations.length > limit) {
        recommendations = recommendations.take(limit).toList();
      }
      
      return Right(recommendations);
    } catch (e) {
      return Left(ServerFailure('Failed to get recommendations: $e'));
    }
  }
  
  /// Track shopping action
  Future<Either<Failure, void>> trackShoppingAction({
    required String recommendationId,
    required ShoppingAction action,
    Map<String, dynamic>? metadata,
  }) async {
    try {
      final recommendation = _activeRecommendations[recommendationId];
      if (recommendation == null) {
        return Left(DatabaseFailure('Recommendation not found'));
      }
      
      // Update recommendation status
      final updatedRecommendation = recommendation.copyWith(
        status: _getStatusFromAction(action),
        lastActionAt: DateTime.now(),
      );
      
      _activeRecommendations[recommendationId] = updatedRecommendation;
      await _saveActiveRecommendations();
      
      // Track analytics
      await _analyticsService.trackEvent(
        eventType: 'shopping_recommendation',
        eventName: action.name,
        properties: {
          'recommendationId': recommendationId,
          'category': recommendation.category.name,
          'priceRange': recommendation.priceRange.name,
          ...?metadata,
        },
      );
      
      // Send follow-up notification if needed
      if (action == ShoppingAction.viewed && _settings.followUpReminders) {
        _scheduleFollowUpReminder(recommendation);
      }
      
      return const Right(null);
    } catch (e) {
      return Left(ServerFailure('Failed to track shopping action: $e'));
    }
  }
  
  /// Check for deals and sales
  Future<Either<Failure, List<ShoppingDeal>>> checkForDeals() async {
    try {
      // In a real app, this would connect to deal APIs or scrape sale information
      // For now, return mock data
      final deals = <ShoppingDeal>[];
      
      // Check active recommendations for potential deals
      for (final recommendation in _activeRecommendations.values) {
        if (recommendation.status == RecommendationStatus.active) {
          // Mock deal detection
          if (DateTime.now().weekday == DateTime.friday) {
            deals.add(ShoppingDeal(
              id: '${recommendation.id}_deal',
              recommendationId: recommendation.id,
              title: '${recommendation.title} - Weekend Sale!',
              description: 'Save 20% on ${recommendation.category.name}',
              discountPercentage: 20,
              originalPrice: recommendation.estimatedPrice,
              salePrice: recommendation.estimatedPrice * 0.8,
              validUntil: DateTime.now().add(const Duration(days: 2)),
              retailer: 'Fashion Store',
              url: 'https://example.com/deal',
            ));
          }
        }
      }
      
      // Send notifications for new deals
      if (deals.isNotEmpty && _settings.dealAlerts) {
        await _sendDealNotification(deals);
      }
      
      return Right(deals);
    } catch (e) {
      return Left(ServerFailure('Failed to check for deals: $e'));
    }
  }
  
  /// Update settings
  Future<Either<Failure, void>> updateSettings(
    ShoppingRecommendationSettings settings,
  ) async {
    try {
      _settings = settings;
      await _saveSettings();
      
      // Restart services if needed
      _analysisTimer?.cancel();
      _dealCheckTimer?.cancel();
      
      if (settings.enabled) {
        _startRecommendationEngine();
      }
      
      return const Right(null);
    } catch (e) {
      return Left(ServerFailure('Failed to update settings: $e'));
    }
  }
  
  /// Get current settings
  ShoppingRecommendationSettings getSettings() => _settings;
  
  // Private methods
  
  void _startRecommendationEngine() {
    // Schedule periodic wardrobe analysis
    _analysisTimer = Timer.periodic(_analysisInterval, (_) {
      if (_settings.automaticAnalysis) {
        analyzeWardrobe();
      }
    });
    
    // Schedule deal checking
    if (_settings.dealAlerts) {
      _dealCheckTimer = Timer.periodic(_dealCheckInterval, (_) {
        checkForDeals();
      });
    }
    
    // Initial analysis
    analyzeWardrobe();
  }
  
  List<WardrobeGap> _identifyWardrobeGaps({
    required List<Garment> garments,
    required Map<String, int> categoryCount,
    required Map<String, int> colorCount,
    required Map<String, int> seasonalCoverage,
  }) {
    final gaps = <WardrobeGap>[];
    
    // Check essential categories
    final essentialCategories = {
      'Shirts': 5,
      'Pants': 3,
      'Shoes': 3,
      'Outerwear': 2,
      'Accessories': 3,
    };
    
    for (final entry in essentialCategories.entries) {
      final currentCount = categoryCount[entry.key] ?? 0;
      if (currentCount < entry.value) {
        gaps.add(WardrobeGap(
          type: GapType.category,
          category: entry.key,
          currentCount: currentCount,
          recommendedCount: entry.value,
          priority: GapPriority.high,
          reason: 'Essential wardrobe item',
        ));
      }
    }
    
    // Check color balance
    final totalGarments = garments.length;
    final neutralColors = ['Black', 'White', 'Gray', 'Navy', 'Beige'];
    var neutralCount = 0;
    
    for (final color in neutralColors) {
      neutralCount += colorCount[color] ?? 0;
    }
    
    final neutralPercentage = totalGarments > 0 ? neutralCount / totalGarments : 0;
    if (neutralPercentage < 0.4) {
      gaps.add(WardrobeGap(
        type: GapType.color,
        category: 'Neutral Colors',
        currentCount: neutralCount,
        recommendedCount: (totalGarments * 0.4).round(),
        priority: GapPriority.medium,
        reason: 'Neutral colors provide versatility',
      ));
    }
    
    // Check seasonal coverage
    final seasons = ['Spring', 'Summer', 'Fall', 'Winter'];
    for (final season in seasons) {
      final coverage = seasonalCoverage[season] ?? 0;
      if (coverage < 5) {
        gaps.add(WardrobeGap(
          type: GapType.seasonal,
          category: '$season Wear',
          currentCount: coverage,
          recommendedCount: 5,
          priority: GapPriority.medium,
          reason: 'Ensure comfort in all seasons',
        ));
      }
    }
    
    // Check occasion coverage
    final occasionGarments = garments.where((g) {
      final tags = g.tags?.split(',') ?? [];
      return tags.any((tag) => 
          ['formal', 'business', 'party', 'wedding'].contains(tag.toLowerCase()));
    }).length;
    
    if (occasionGarments < 3) {
      gaps.add(WardrobeGap(
        type: GapType.occasion,
        category: 'Formal/Occasion Wear',
        currentCount: occasionGarments,
        recommendedCount: 3,
        priority: GapPriority.low,
        reason: 'Be prepared for special occasions',
      ));
    }
    
    return gaps;
  }
  
  Future<List<ShoppingRecommendation>> _generateRecommendations(
    List<WardrobeGap> gaps,
  ) async {
    final recommendations = <ShoppingRecommendation>[];
    
    for (final gap in gaps) {
      // Generate 1-2 recommendations per gap
      final recommendationCount = gap.priority == GapPriority.high ? 2 : 1;
      
      for (int i = 0; i < recommendationCount; i++) {
        final recommendation = ShoppingRecommendation(
          id: '${gap.category}_${DateTime.now().millisecondsSinceEpoch}_$i',
          title: _generateRecommendationTitle(gap),
          description: _generateRecommendationDescription(gap),
          category: _mapGapToShoppingCategory(gap),
          priceRange: _suggestPriceRange(gap),
          priority: _mapGapPriorityToScore(gap.priority),
          occasions: _suggestOccasions(gap),
          colors: _suggestColors(gap),
          estimatedPrice: _estimatePrice(gap),
          status: RecommendationStatus.active,
          createdAt: DateTime.now(),
        );
        
        recommendations.add(recommendation);
        _activeRecommendations[recommendation.id] = recommendation;
      }
    }
    
    await _saveActiveRecommendations();
    return recommendations;
  }
  
  String _generateRecommendationTitle(WardrobeGap gap) {
    switch (gap.type) {
      case GapType.category:
        return 'Add ${gap.category} to Your Wardrobe';
      case GapType.color:
        return 'Expand Your ${gap.category} Options';
      case GapType.seasonal:
        return 'Prepare for ${gap.category}';
      case GapType.occasion:
        return 'Complete Your ${gap.category} Collection';
    }
  }
  
  String _generateRecommendationDescription(WardrobeGap gap) {
    final needed = gap.recommendedCount - gap.currentCount;
    return '${gap.reason}. You currently have ${gap.currentCount}, '
           'we recommend adding $needed more.';
  }
  
  ShoppingCategory _mapGapToShoppingCategory(WardrobeGap gap) {
    final categoryMap = {
      'Shirts': ShoppingCategory.tops,
      'Pants': ShoppingCategory.bottoms,
      'Shoes': ShoppingCategory.footwear,
      'Outerwear': ShoppingCategory.outerwear,
      'Accessories': ShoppingCategory.accessories,
      'Formal/Occasion Wear': ShoppingCategory.formalwear,
    };
    
    return categoryMap[gap.category] ?? ShoppingCategory.other;
  }
  
  PriceRange _suggestPriceRange(WardrobeGap gap) {
    // Analyze user's existing wardrobe price points
    // For now, return medium as default
    return PriceRange.medium;
  }
  
  double _mapGapPriorityToScore(GapPriority priority) {
    switch (priority) {
      case GapPriority.high:
        return 0.9;
      case GapPriority.medium:
        return 0.6;
      case GapPriority.low:
        return 0.3;
    }
  }
  
  List<String> _suggestOccasions(WardrobeGap gap) {
    if (gap.type == GapType.occasion) {
      return ['formal', 'business', 'party', 'wedding'];
    }
    
    switch (gap.category) {
      case 'Shirts':
        return ['casual', 'work', 'weekend'];
      case 'Pants':
        return ['casual', 'work', 'evening'];
      case 'Shoes':
        return ['daily', 'work', 'special'];
      default:
        return ['versatile'];
    }
  }
  
  List<String> _suggestColors(WardrobeGap gap) {
    if (gap.type == GapType.color) {
      return ['Black', 'White', 'Gray', 'Navy'];
    }
    
    // Suggest versatile colors
    return ['Black', 'White', 'Navy'];
  }
  
  double _estimatePrice(WardrobeGap gap) {
    // Estimate based on category and quality
    final priceMap = {
      'Shirts': 50.0,
      'Pants': 80.0,
      'Shoes': 100.0,
      'Outerwear': 150.0,
      'Accessories': 30.0,
      'Formal/Occasion Wear': 200.0,
    };
    
    return priceMap[gap.category] ?? 75.0;
  }
  
  RecommendationStatus _getStatusFromAction(ShoppingAction action) {
    switch (action) {
      case ShoppingAction.viewed:
        return RecommendationStatus.viewed;
      case ShoppingAction.saved:
        return RecommendationStatus.saved;
      case ShoppingAction.purchased:
        return RecommendationStatus.purchased;
      case ShoppingAction.dismissed:
        return RecommendationStatus.dismissed;
    }
  }
  
  void _scheduleFollowUpReminder(ShoppingRecommendation recommendation) {
    // Schedule a reminder for 3 days later
    Timer(const Duration(days: 3), () async {
      if (_activeRecommendations[recommendation.id]?.status == 
          RecommendationStatus.viewed) {
        await _notificationService.sendOutfitSuggestion(
          title: 'Still interested in ${recommendation.title}?',
          body: 'Tap to view similar options or dismiss this recommendation',
          data: {
            'type': 'shopping_followup',
            'recommendationId': recommendation.id,
          },
        );
      }
    });
  }
  
  Future<void> _sendDealNotification(List<ShoppingDeal> deals) async {
    String title;
    String body;
    
    if (deals.length == 1) {
      final deal = deals.first;
      title = '${deal.discountPercentage}% Off Alert! 🛍️';
      body = deal.title;
    } else {
      title = '${deals.length} New Deals Found! 🛍️';
      body = 'Save up to ${deals.map((d) => d.discountPercentage).reduce((a, b) => a > b ? a : b)}% on recommended items';
    }
    
    await _notificationService.sendOutfitSuggestion(
      title: title,
      body: body,
      data: {
        'type': 'shopping_deals',
        'dealCount': deals.length,
        'dealIds': deals.map((d) => d.id).toList(),
      },
    );
  }
  
  WardrobeAnalysis _getCachedAnalysis(String userId) {
    // Return cached analysis
    // In a real app, this would retrieve from persistent storage
    return WardrobeAnalysis(
      totalGarments: 0,
      categoryDistribution: {},
      colorDistribution: {},
      brandDistribution: {},
      seasonalCoverage: {},
      gaps: _wardrobeGaps[userId] ?? [],
      recommendations: _activeRecommendations.values.toList(),
      analyzedAt: _lastAnalysisTime[userId] ?? DateTime.now(),
    );
  }
  
  Future<void> _loadSettings() async {
    final prefs = await SharedPreferences.getInstance();
    final settingsJson = prefs.getString('shopping_recommendation_settings');
    
    if (settingsJson != null) {
      _settings = ShoppingRecommendationSettings.fromJson(json.decode(settingsJson));
    }
  }
  
  Future<void> _saveSettings() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(
      'shopping_recommendation_settings',
      json.encode(_settings.toJson()),
    );
  }
  
  Future<void> _loadActiveRecommendations() async {
    final prefs = await SharedPreferences.getInstance();
    final recommendationsJson = prefs.getString('active_shopping_recommendations');
    
    if (recommendationsJson != null) {
      final Map<String, dynamic> recommendationsMap = json.decode(recommendationsJson);
      recommendationsMap.forEach((key, value) {
        _activeRecommendations[key] = ShoppingRecommendation.fromJson(value);
      });
    }
  }
  
  Future<void> _saveActiveRecommendations() async {
    final prefs = await SharedPreferences.getInstance();
    final recommendationsMap = <String, dynamic>{};
    
    _activeRecommendations.forEach((key, value) {
      recommendationsMap[key] = value.toJson();
    });
    
    await prefs.setString(
      'active_shopping_recommendations',
      json.encode(recommendationsMap),
    );
  }
  
  void dispose() {
    _analysisTimer?.cancel();
    _dealCheckTimer?.cancel();
  }
}

/// Shopping recommendation settings
class ShoppingRecommendationSettings {
  final bool enabled;
  final bool automaticAnalysis;
  final bool personalizedRecommendations;
  final bool dealAlerts;
  final bool followUpReminders;
  final bool budgetTracking;
  final double? monthlyBudget;
  
  const ShoppingRecommendationSettings({
    this.enabled = true,
    this.automaticAnalysis = true,
    this.personalizedRecommendations = true,
    this.dealAlerts = true,
    this.followUpReminders = false,
    this.budgetTracking = false,
    this.monthlyBudget,
  });
  
  Map<String, dynamic> toJson() => {
    'enabled': enabled,
    'automaticAnalysis': automaticAnalysis,
    'personalizedRecommendations': personalizedRecommendations,
    'dealAlerts': dealAlerts,
    'followUpReminders': followUpReminders,
    'budgetTracking': budgetTracking,
    'monthlyBudget': monthlyBudget,
  };
  
  factory ShoppingRecommendationSettings.fromJson(Map<String, dynamic> json) {
    return ShoppingRecommendationSettings(
      enabled: json['enabled'] ?? true,
      automaticAnalysis: json['automaticAnalysis'] ?? true,
      personalizedRecommendations: json['personalizedRecommendations'] ?? true,
      dealAlerts: json['dealAlerts'] ?? true,
      followUpReminders: json['followUpReminders'] ?? false,
      budgetTracking: json['budgetTracking'] ?? false,
      monthlyBudget: json['monthlyBudget']?.toDouble(),
    );
  }
  
  ShoppingRecommendationSettings copyWith({
    bool? enabled,
    bool? automaticAnalysis,
    bool? personalizedRecommendations,
    bool? dealAlerts,
    bool? followUpReminders,
    bool? budgetTracking,
    double? monthlyBudget,
  }) {
    return ShoppingRecommendationSettings(
      enabled: enabled ?? this.enabled,
      automaticAnalysis: automaticAnalysis ?? this.automaticAnalysis,
      personalizedRecommendations: personalizedRecommendations ?? this.personalizedRecommendations,
      dealAlerts: dealAlerts ?? this.dealAlerts,
      followUpReminders: followUpReminders ?? this.followUpReminders,
      budgetTracking: budgetTracking ?? this.budgetTracking,
      monthlyBudget: monthlyBudget ?? this.monthlyBudget,
    );
  }
}

/// Wardrobe analysis result
class WardrobeAnalysis {
  final int totalGarments;
  final Map<String, int> categoryDistribution;
  final Map<String, int> colorDistribution;
  final Map<String, int> brandDistribution;
  final Map<String, int> seasonalCoverage;
  final List<WardrobeGap> gaps;
  final List<ShoppingRecommendation> recommendations;
  final DateTime analyzedAt;
  
  const WardrobeAnalysis({
    required this.totalGarments,
    required this.categoryDistribution,
    required this.colorDistribution,
    required this.brandDistribution,
    required this.seasonalCoverage,
    required this.gaps,
    required this.recommendations,
    required this.analyzedAt,
  });
}

/// Wardrobe gap
class WardrobeGap {
  final GapType type;
  final String category;
  final int currentCount;
  final int recommendedCount;
  final GapPriority priority;
  final String reason;
  
  const WardrobeGap({
    required this.type,
    required this.category,
    required this.currentCount,
    required this.recommendedCount,
    required this.priority,
    required this.reason,
  });
}

/// Shopping recommendation
class ShoppingRecommendation {
  final String id;
  final String title;
  final String description;
  final ShoppingCategory category;
  final PriceRange priceRange;
  final double priority;
  final List<String> occasions;
  final List<String> colors;
  final double estimatedPrice;
  final RecommendationStatus status;
  final DateTime createdAt;
  final DateTime? lastActionAt;
  
  const ShoppingRecommendation({
    required this.id,
    required this.title,
    required this.description,
    required this.category,
    required this.priceRange,
    required this.priority,
    required this.occasions,
    required this.colors,
    required this.estimatedPrice,
    required this.status,
    required this.createdAt,
    this.lastActionAt,
  });
  
  Map<String, dynamic> toJson() => {
    'id': id,
    'title': title,
    'description': description,
    'category': category.name,
    'priceRange': priceRange.name,
    'priority': priority,
    'occasions': occasions,
    'colors': colors,
    'estimatedPrice': estimatedPrice,
    'status': status.name,
    'createdAt': createdAt.toIso8601String(),
    'lastActionAt': lastActionAt?.toIso8601String(),
  };
  
  factory ShoppingRecommendation.fromJson(Map<String, dynamic> json) {
    return ShoppingRecommendation(
      id: json['id'],
      title: json['title'],
      description: json['description'],
      category: ShoppingCategory.values.firstWhere(
        (c) => c.name == json['category'],
      ),
      priceRange: PriceRange.values.firstWhere(
        (p) => p.name == json['priceRange'],
      ),
      priority: json['priority'].toDouble(),
      occasions: List<String>.from(json['occasions']),
      colors: List<String>.from(json['colors']),
      estimatedPrice: json['estimatedPrice'].toDouble(),
      status: RecommendationStatus.values.firstWhere(
        (s) => s.name == json['status'],
      ),
      createdAt: DateTime.parse(json['createdAt']),
      lastActionAt: json['lastActionAt'] != null
          ? DateTime.parse(json['lastActionAt'])
          : null,
    );
  }
  
  ShoppingRecommendation copyWith({
    RecommendationStatus? status,
    DateTime? lastActionAt,
  }) {
    return ShoppingRecommendation(
      id: id,
      title: title,
      description: description,
      category: category,
      priceRange: priceRange,
      priority: priority,
      occasions: occasions,
      colors: colors,
      estimatedPrice: estimatedPrice,
      status: status ?? this.status,
      createdAt: createdAt,
      lastActionAt: lastActionAt ?? this.lastActionAt,
    );
  }
}

/// Shopping deal
class ShoppingDeal {
  final String id;
  final String recommendationId;
  final String title;
  final String description;
  final int discountPercentage;
  final double originalPrice;
  final double salePrice;
  final DateTime validUntil;
  final String retailer;
  final String? url;
  
  const ShoppingDeal({
    required this.id,
    required this.recommendationId,
    required this.title,
    required this.description,
    required this.discountPercentage,
    required this.originalPrice,
    required this.salePrice,
    required this.validUntil,
    required this.retailer,
    this.url,
  });
}

/// Gap types
enum GapType {
  category,
  color,
  seasonal,
  occasion,
}

/// Gap priority
enum GapPriority {
  high,
  medium,
  low,
}

/// Shopping categories
enum ShoppingCategory {
  tops,
  bottoms,
  dresses,
  outerwear,
  footwear,
  accessories,
  activewear,
  formalwear,
  other,
}

/// Price ranges
enum PriceRange {
  budget,
  medium,
  premium,
  luxury,
}

/// Shopping actions
enum ShoppingAction {
  viewed,
  saved,
  purchased,
  dismissed,
}

/// Recommendation status
enum RecommendationStatus {
  active,
  viewed,
  saved,
  purchased,
  dismissed,
}