import 'package:flutter/material.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:koutu/services/notification/push_notification_service.dart';
import 'package:koutu/services/weather/weather_service.dart';
import 'package:koutu/services/analytics/analytics_service.dart';
import 'package:koutu/data/datasources/local/database/app_database.dart';
import 'package:dartz/dartz.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'dart:async';
import 'dart:convert';

/// Service for seasonal wardrobe transition alerts
class SeasonalTransitionService {
  final PushNotificationService _notificationService;
  final WeatherService _weatherService;
  final AnalyticsService _analyticsService;
  final AppDatabase _database;
  
  // Settings
  SeasonalTransitionSettings _settings = const SeasonalTransitionSettings();
  
  // Season tracking
  String? _currentSeason;
  DateTime? _lastSeasonCheck;
  DateTime? _lastTransitionNotification;
  
  // Timers
  Timer? _seasonCheckTimer;
  
  SeasonalTransitionService({
    required PushNotificationService notificationService,
    required WeatherService weatherService,
    required AnalyticsService analyticsService,
    required AppDatabase database,
  })  : _notificationService = notificationService,
        _weatherService = weatherService,
        _analyticsService = analyticsService,
        _database = database;
  
  /// Initialize seasonal transition service
  Future<void> initialize() async {
    await _loadSettings();
    await _loadSeasonData();
    
    if (_settings.enabled) {
      _startSeasonMonitoring();
    }
  }
  
  /// Check for seasonal transitions
  Future<void> checkSeasonalTransition() async {
    if (!_settings.enabled) return;
    
    // Don't check too frequently
    if (_lastSeasonCheck != null &&
        DateTime.now().difference(_lastSeasonCheck!) < const Duration(days: 1)) {
      return;
    }
    
    _lastSeasonCheck = DateTime.now();
    
    // Get current weather data
    final weatherResult = await _weatherService.getCurrentWeather();
    if (weatherResult.isLeft()) return;
    
    final weather = weatherResult.getOrElse(() => throw Exception());
    
    // Determine current season based on temperature and date
    final detectedSeason = _detectSeason(weather.temperature);
    
    if (_currentSeason != null && _currentSeason != detectedSeason) {
      // Season has changed
      await _handleSeasonTransition(_currentSeason!, detectedSeason);
    }
    
    _currentSeason = detectedSeason;
    await _saveSeasonData();
    
    // Check wardrobe preparation
    await _checkWardrobePreparation(detectedSeason);
  }
  
  /// Get wardrobe transition recommendations
  Future<Either<Failure, WardrobeTransitionPlan>> getTransitionPlan({
    required String fromSeason,
    required String toSeason,
  }) async {
    try {
      // Analyze current wardrobe
      final garments = await _database.select(_database.garments).get();
      
      // Categorize by season
      final currentSeasonItems = <Garment>[];
      final nextSeasonItems = <Garment>[];
      final yearRoundItems = <Garment>[];
      final itemsToStore = <Garment>[];
      final itemsToRetrieve = <Garment>[];
      
      for (final garment in garments) {
        final seasons = garment.seasons?.split(',') ?? [];
        
        if (seasons.contains('All') || seasons.length >= 3) {
          yearRoundItems.add(garment);
        } else if (seasons.contains(fromSeason)) {
          currentSeasonItems.add(garment);
          if (!seasons.contains(toSeason)) {
            itemsToStore.add(garment);
          }
        } else if (seasons.contains(toSeason)) {
          nextSeasonItems.add(garment);
          itemsToRetrieve.add(garment);
        }
      }
      
      // Generate recommendations
      final recommendations = <String>[];
      final tasks = <TransitionTask>[];
      
      // Storage recommendations
      if (itemsToStore.isNotEmpty) {
        recommendations.add(
          'Store ${itemsToStore.length} ${fromSeason.toLowerCase()} items',
        );
        
        tasks.add(TransitionTask(
          id: 'store_${fromSeason.toLowerCase()}',
          title: 'Store ${fromSeason} Wardrobe',
          description: 'Clean and store ${itemsToStore.length} seasonal items',
          items: itemsToStore.map((g) => g.id).toList(),
          type: TransitionTaskType.storage,
          priority: TransitionTaskPriority.high,
        ));
      }
      
      // Retrieval recommendations
      if (itemsToRetrieve.isNotEmpty) {
        recommendations.add(
          'Retrieve ${itemsToRetrieve.length} ${toSeason.toLowerCase()} items',
        );
        
        tasks.add(TransitionTask(
          id: 'retrieve_${toSeason.toLowerCase()}',
          title: 'Retrieve ${toSeason} Wardrobe',
          description: 'Unpack and prepare ${itemsToRetrieve.length} seasonal items',
          items: itemsToRetrieve.map((g) => g.id).toList(),
          type: TransitionTaskType.retrieval,
          priority: TransitionTaskPriority.high,
        ));
      }
      
      // Maintenance recommendations
      final itemsNeedingMaintenance = nextSeasonItems.where((garment) {
        // Check last cleaned date
        return true; // Simplified for now
      }).toList();
      
      if (itemsNeedingMaintenance.isNotEmpty) {
        recommendations.add(
          'Clean/maintain ${itemsNeedingMaintenance.length} items before use',
        );
        
        tasks.add(TransitionTask(
          id: 'maintain_${toSeason.toLowerCase()}',
          title: 'Seasonal Maintenance',
          description: 'Clean and prepare items for the new season',
          items: itemsNeedingMaintenance.map((g) => g.id).toList(),
          type: TransitionTaskType.maintenance,
          priority: TransitionTaskPriority.medium,
        ));
      }
      
      // Shopping recommendations
      final missingEssentials = _getMissingEssentials(toSeason, nextSeasonItems);
      if (missingEssentials.isNotEmpty) {
        recommendations.add(
          'Consider adding: ${missingEssentials.join(", ")}',
        );
        
        tasks.add(TransitionTask(
          id: 'shop_${toSeason.toLowerCase()}',
          title: 'Season Essentials Shopping',
          description: 'Items to consider for your ${toSeason.toLowerCase()} wardrobe',
          items: missingEssentials,
          type: TransitionTaskType.shopping,
          priority: TransitionTaskPriority.low,
        ));
      }
      
      final plan = WardrobeTransitionPlan(
        fromSeason: fromSeason,
        toSeason: toSeason,
        recommendations: recommendations,
        tasks: tasks,
        estimatedTime: _estimateTransitionTime(tasks),
        createdAt: DateTime.now(),
      );
      
      return Right(plan);
    } catch (e) {
      return Left(DatabaseFailure('Failed to create transition plan: $e'));
    }
  }
  
  /// Update settings
  Future<Either<Failure, void>> updateSettings(
    SeasonalTransitionSettings settings,
  ) async {
    try {
      _settings = settings;
      await _saveSettings();
      
      // Restart monitoring if needed
      _seasonCheckTimer?.cancel();
      if (settings.enabled) {
        _startSeasonMonitoring();
      }
      
      return const Right(null);
    } catch (e) {
      return Left(ServerFailure('Failed to update settings: $e'));
    }
  }
  
  /// Get current settings
  SeasonalTransitionSettings getSettings() => _settings;
  
  /// Get current season
  String getCurrentSeason() {
    return _currentSeason ?? _getSeasonByDate(DateTime.now());
  }
  
  // Private methods
  
  void _startSeasonMonitoring() {
    // Check daily
    _seasonCheckTimer = Timer.periodic(
      const Duration(days: 1),
      (_) => checkSeasonalTransition(),
    );
    
    // Initial check
    checkSeasonalTransition();
  }
  
  String _detectSeason(double temperature) {
    final month = DateTime.now().month;
    
    // Northern hemisphere logic (adjust for location)
    if (month >= 3 && month <= 5) {
      return 'Spring';
    } else if (month >= 6 && month <= 8) {
      return 'Summer';
    } else if (month >= 9 && month <= 11) {
      return 'Fall';
    } else {
      return 'Winter';
    }
  }
  
  String _getSeasonByDate(DateTime date) {
    final month = date.month;
    
    if (month >= 3 && month <= 5) {
      return 'Spring';
    } else if (month >= 6 && month <= 8) {
      return 'Summer';
    } else if (month >= 9 && month <= 11) {
      return 'Fall';
    } else {
      return 'Winter';
    }
  }
  
  Future<void> _handleSeasonTransition(
    String fromSeason,
    String toSeason,
  ) async {
    // Don't send too many notifications
    if (_lastTransitionNotification != null &&
        DateTime.now().difference(_lastTransitionNotification!) <
            const Duration(days: 7)) {
      return;
    }
    
    // Track event
    await _analyticsService.trackEvent(
      eventType: 'seasonal_transition',
      eventName: 'season_change',
      properties: {
        'from_season': fromSeason,
        'to_season': toSeason,
      },
    );
    
    // Send transition notification
    await _notificationService.sendOutfitSuggestion(
      title: 'Season Change Detected! 🍂',
      body: 'Time to transition from $fromSeason to $toSeason wardrobe',
      data: {
        'type': 'seasonal_transition',
        'fromSeason': fromSeason,
        'toSeason': toSeason,
      },
    );
    
    _lastTransitionNotification = DateTime.now();
    
    // Schedule preparation reminders
    if (_settings.preparationReminders) {
      await _schedulePreparationReminders(toSeason);
    }
  }
  
  Future<void> _checkWardrobePreparation(String season) async {
    if (!_settings.wardrobeCheckReminders) return;
    
    // Get wardrobe stats
    final garments = await _database.select(_database.garments).get();
    final seasonalItems = garments.where((g) {
      final seasons = g.seasons?.split(',') ?? [];
      return seasons.contains(season) || seasons.contains('All');
    }).toList();
    
    // Check if wardrobe is prepared
    if (seasonalItems.length < 10) {
      // Arbitrary threshold
      await _notificationService.sendOutfitSuggestion(
        title: 'Wardrobe Check 👔',
        body: 'Your $season wardrobe might need some additions',
        data: {
          'type': 'wardrobe_check',
          'season': season,
          'itemCount': seasonalItems.length,
        },
      );
    }
  }
  
  Future<void> _schedulePreparationReminders(String upcomingSeason) async {
    // Schedule reminders for the next 2 weeks
    for (int days in [3, 7, 14]) {
      Timer(Duration(days: days), () async {
        await _notificationService.sendOutfitSuggestion(
          title: '$upcomingSeason Preparation Reminder',
          body: 'Time to prepare your wardrobe for the upcoming season',
          data: {
            'type': 'season_preparation',
            'season': upcomingSeason,
            'daysUntil': days,
          },
        );
      });
    }
  }
  
  List<String> _getMissingEssentials(String season, List<Garment> currentItems) {
    final essentials = <String>[];
    
    // Define essentials by season
    final seasonEssentials = {
      'Spring': [
        'Light jacket',
        'Rain jacket',
        'Transitional sweater',
        'Light scarf',
      ],
      'Summer': [
        'Shorts',
        'Swimwear',
        'Sunglasses',
        'Light shirts',
        'Sandals',
      ],
      'Fall': [
        'Sweater',
        'Light coat',
        'Boots',
        'Scarf',
        'Long pants',
      ],
      'Winter': [
        'Heavy coat',
        'Winter boots',
        'Gloves',
        'Winter hat',
        'Thermal wear',
      ],
    };
    
    final required = seasonEssentials[season] ?? [];
    final existingCategories = currentItems.map((g) => g.category).toSet();
    
    for (final essential in required) {
      if (!existingCategories.any((cat) => 
          cat?.toLowerCase().contains(essential.toLowerCase()) ?? false)) {
        essentials.add(essential);
      }
    }
    
    return essentials;
  }
  
  Duration _estimateTransitionTime(List<TransitionTask> tasks) {
    var totalMinutes = 0;
    
    for (final task in tasks) {
      switch (task.type) {
        case TransitionTaskType.storage:
          totalMinutes += task.items.length * 5; // 5 min per item
          break;
        case TransitionTaskType.retrieval:
          totalMinutes += task.items.length * 3; // 3 min per item
          break;
        case TransitionTaskType.maintenance:
          totalMinutes += task.items.length * 10; // 10 min per item
          break;
        case TransitionTaskType.shopping:
          totalMinutes += 60; // 1 hour for shopping
          break;
      }
    }
    
    return Duration(minutes: totalMinutes);
  }
  
  Future<void> _loadSettings() async {
    final prefs = await SharedPreferences.getInstance();
    final settingsJson = prefs.getString('seasonal_transition_settings');
    
    if (settingsJson != null) {
      _settings = SeasonalTransitionSettings.fromJson(json.decode(settingsJson));
    }
  }
  
  Future<void> _saveSettings() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(
      'seasonal_transition_settings',
      json.encode(_settings.toJson()),
    );
  }
  
  Future<void> _loadSeasonData() async {
    final prefs = await SharedPreferences.getInstance();
    _currentSeason = prefs.getString('current_season');
    
    final lastCheckStr = prefs.getString('last_season_check');
    if (lastCheckStr != null) {
      _lastSeasonCheck = DateTime.parse(lastCheckStr);
    }
    
    final lastNotificationStr = prefs.getString('last_transition_notification');
    if (lastNotificationStr != null) {
      _lastTransitionNotification = DateTime.parse(lastNotificationStr);
    }
  }
  
  Future<void> _saveSeasonData() async {
    final prefs = await SharedPreferences.getInstance();
    
    if (_currentSeason != null) {
      await prefs.setString('current_season', _currentSeason!);
    }
    
    if (_lastSeasonCheck != null) {
      await prefs.setString('last_season_check', _lastSeasonCheck!.toIso8601String());
    }
    
    if (_lastTransitionNotification != null) {
      await prefs.setString(
        'last_transition_notification',
        _lastTransitionNotification!.toIso8601String(),
      );
    }
  }
  
  void dispose() {
    _seasonCheckTimer?.cancel();
  }
}

/// Seasonal transition settings
class SeasonalTransitionSettings {
  final bool enabled;
  final bool wardrobeCheckReminders;
  final bool preparationReminders;
  final bool maintenanceReminders;
  final int reminderDaysBefore;
  
  const SeasonalTransitionSettings({
    this.enabled = true,
    this.wardrobeCheckReminders = true,
    this.preparationReminders = true,
    this.maintenanceReminders = true,
    this.reminderDaysBefore = 14,
  });
  
  Map<String, dynamic> toJson() => {
    'enabled': enabled,
    'wardrobeCheckReminders': wardrobeCheckReminders,
    'preparationReminders': preparationReminders,
    'maintenanceReminders': maintenanceReminders,
    'reminderDaysBefore': reminderDaysBefore,
  };
  
  factory SeasonalTransitionSettings.fromJson(Map<String, dynamic> json) {
    return SeasonalTransitionSettings(
      enabled: json['enabled'] ?? true,
      wardrobeCheckReminders: json['wardrobeCheckReminders'] ?? true,
      preparationReminders: json['preparationReminders'] ?? true,
      maintenanceReminders: json['maintenanceReminders'] ?? true,
      reminderDaysBefore: json['reminderDaysBefore'] ?? 14,
    );
  }
  
  SeasonalTransitionSettings copyWith({
    bool? enabled,
    bool? wardrobeCheckReminders,
    bool? preparationReminders,
    bool? maintenanceReminders,
    int? reminderDaysBefore,
  }) {
    return SeasonalTransitionSettings(
      enabled: enabled ?? this.enabled,
      wardrobeCheckReminders: wardrobeCheckReminders ?? this.wardrobeCheckReminders,
      preparationReminders: preparationReminders ?? this.preparationReminders,
      maintenanceReminders: maintenanceReminders ?? this.maintenanceReminders,
      reminderDaysBefore: reminderDaysBefore ?? this.reminderDaysBefore,
    );
  }
}

/// Wardrobe transition plan
class WardrobeTransitionPlan {
  final String fromSeason;
  final String toSeason;
  final List<String> recommendations;
  final List<TransitionTask> tasks;
  final Duration estimatedTime;
  final DateTime createdAt;
  
  const WardrobeTransitionPlan({
    required this.fromSeason,
    required this.toSeason,
    required this.recommendations,
    required this.tasks,
    required this.estimatedTime,
    required this.createdAt,
  });
}

/// Transition task
class TransitionTask {
  final String id;
  final String title;
  final String description;
  final List<String> items;
  final TransitionTaskType type;
  final TransitionTaskPriority priority;
  bool isCompleted;
  
  TransitionTask({
    required this.id,
    required this.title,
    required this.description,
    required this.items,
    required this.type,
    required this.priority,
    this.isCompleted = false,
  });
}

/// Transition task types
enum TransitionTaskType {
  storage,
  retrieval,
  maintenance,
  shopping,
}

/// Transition task priority
enum TransitionTaskPriority {
  high,
  medium,
  low,
}