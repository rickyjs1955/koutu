import 'package:flutter/foundation.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:koutu/data/datasources/local/database/app_database.dart';
import 'package:koutu/services/auth/auth_service.dart';
import 'package:dartz/dartz.dart';
import 'package:dio/dio.dart';
import 'package:koutu/core/config/environment.dart';
import 'dart:async';
import 'package:shared_preferences/shared_preferences.dart';

/// Service for tracking user analytics and behavior
class AnalyticsService {
  final AppDatabase _database;
  final AuthService _authService;
  final Dio _dio;
  
  // Analytics settings
  bool _analyticsEnabled = false;
  bool _crashReportingEnabled = false;
  
  // Event queue for batch uploading
  final List<AnalyticsEvent> _eventQueue = [];
  Timer? _uploadTimer;
  static const int _batchSize = 50;
  static const Duration _uploadInterval = Duration(minutes: 5);
  
  // Session tracking
  String? _sessionId;
  DateTime? _sessionStart;
  static const Duration _sessionTimeout = Duration(minutes: 30);
  Timer? _sessionTimer;
  
  AnalyticsService({
    required AppDatabase database,
    required AuthService authService,
    required Dio dio,
  })  : _database = database,
        _authService = authService,
        _dio = dio;
  
  /// Initialize analytics service
  Future<void> initialize() async {
    await _loadSettings();
    
    if (_analyticsEnabled) {
      _startSession();
      _startUploadTimer();
    }
    
    // Listen to auth state changes
    _authService.authState.listen((isAuthenticated) {
      if (isAuthenticated) {
        _startSession();
      } else {
        _endSession();
      }
    });
  }
  
  /// Track event
  Future<Either<Failure, void>> trackEvent({
    required String eventType,
    required String eventName,
    Map<String, dynamic>? properties,
  }) async {
    if (!_analyticsEnabled) {
      return const Right(null);
    }
    
    try {
      final event = AnalyticsEvent(
        id: DateTime.now().millisecondsSinceEpoch.toString(),
        userId: _authService.currentUser?.id ?? 'anonymous',
        sessionId: _sessionId,
        eventType: eventType,
        eventName: eventName,
        properties: properties,
        timestamp: DateTime.now(),
      );
      
      // Save to local database
      await _saveEvent(event);
      
      // Add to queue
      _eventQueue.add(event);
      
      // Upload if batch size reached
      if (_eventQueue.length >= _batchSize) {
        await _uploadEvents();
      }
      
      return const Right(null);
    } catch (e) {
      return Left(DatabaseFailure('Failed to track event: $e'));
    }
  }
  
  /// Track screen view
  Future<void> trackScreenView({
    required String screenName,
    Map<String, dynamic>? properties,
  }) async {
    await trackEvent(
      eventType: EventType.screenView.name,
      eventName: screenName,
      properties: properties,
    );
  }
  
  /// Track user action
  Future<void> trackAction({
    required String action,
    String? category,
    String? label,
    num? value,
    Map<String, dynamic>? properties,
  }) async {
    final eventProperties = {
      if (category != null) 'category': category,
      if (label != null) 'label': label,
      if (value != null) 'value': value,
      ...?properties,
    };
    
    await trackEvent(
      eventType: EventType.action.name,
      eventName: action,
      properties: eventProperties,
    );
  }
  
  /// Track timing
  Future<void> trackTiming({
    required String category,
    required String variable,
    required int milliseconds,
    String? label,
  }) async {
    await trackEvent(
      eventType: EventType.timing.name,
      eventName: '$category.$variable',
      properties: {
        'duration': milliseconds,
        if (label != null) 'label': label,
      },
    );
  }
  
  /// Track error
  Future<void> trackError({
    required String error,
    String? stackTrace,
    bool fatal = false,
    Map<String, dynamic>? properties,
  }) async {
    if (!_crashReportingEnabled) return;
    
    await trackEvent(
      eventType: EventType.error.name,
      eventName: error,
      properties: {
        'fatal': fatal,
        if (stackTrace != null) 'stackTrace': stackTrace,
        ...?properties,
      },
    );
  }
  
  /// Track user properties
  Future<Either<Failure, void>> setUserProperties(
    Map<String, dynamic> properties,
  ) async {
    if (!_analyticsEnabled) {
      return const Right(null);
    }
    
    try {
      final authToken = await _authService.getAuthToken();
      
      final response = await _dio.put(
        '${Environment.apiUrl}/analytics/user-properties',
        data: {
          'userId': _authService.currentUser?.id,
          'properties': properties,
        },
        options: Options(
          headers: {'Authorization': 'Bearer $authToken'},
        ),
      );
      
      if (response.statusCode == 200) {
        return const Right(null);
      } else {
        throw Exception('Failed to set user properties: ${response.statusCode}');
      }
    } catch (e) {
      return Left(ServerFailure('Failed to set user properties: $e'));
    }
  }
  
  /// Get analytics summary
  Future<Either<Failure, AnalyticsSummary>> getAnalyticsSummary({
    DateTime? startDate,
    DateTime? endDate,
  }) async {
    try {
      final authToken = await _authService.getAuthToken();
      
      final queryParams = {
        if (startDate != null) 'startDate': startDate.toIso8601String(),
        if (endDate != null) 'endDate': endDate.toIso8601String(),
      };
      
      final response = await _dio.get(
        '${Environment.apiUrl}/analytics/summary',
        queryParameters: queryParams,
        options: Options(
          headers: {'Authorization': 'Bearer $authToken'},
        ),
      );
      
      if (response.statusCode == 200) {
        final summary = AnalyticsSummary.fromJson(response.data);
        return Right(summary);
      } else {
        throw Exception('Failed to get summary: ${response.statusCode}');
      }
    } catch (e) {
      return Left(ServerFailure('Failed to get analytics summary: $e'));
    }
  }
  
  /// Get user behavior insights
  Future<Either<Failure, UserBehaviorInsights>> getUserInsights() async {
    try {
      final authToken = await _authService.getAuthToken();
      
      final response = await _dio.get(
        '${Environment.apiUrl}/analytics/insights',
        options: Options(
          headers: {'Authorization': 'Bearer $authToken'},
        ),
      );
      
      if (response.statusCode == 200) {
        final insights = UserBehaviorInsights.fromJson(response.data);
        return Right(insights);
      } else {
        throw Exception('Failed to get insights: ${response.statusCode}');
      }
    } catch (e) {
      return Left(ServerFailure('Failed to get user insights: $e'));
    }
  }
  
  /// Update analytics settings
  Future<void> updateSettings({
    required bool analyticsEnabled,
    required bool crashReportingEnabled,
  }) async {
    _analyticsEnabled = analyticsEnabled;
    _crashReportingEnabled = crashReportingEnabled;
    
    await _saveSettings();
    
    if (_analyticsEnabled) {
      _startSession();
      _startUploadTimer();
    } else {
      _endSession();
      _stopUploadTimer();
    }
  }
  
  /// Get analytics settings
  (bool analyticsEnabled, bool crashReportingEnabled) getSettings() {
    return (_analyticsEnabled, _crashReportingEnabled);
  }
  
  /// Force upload events
  Future<void> flush() async {
    await _uploadEvents();
  }
  
  // Private methods
  
  void _startSession() {
    _sessionId = DateTime.now().millisecondsSinceEpoch.toString();
    _sessionStart = DateTime.now();
    
    // Track session start
    trackEvent(
      eventType: EventType.session.name,
      eventName: 'session_start',
      properties: {
        'platform': defaultTargetPlatform.name,
        'appVersion': Environment.appVersion,
      },
    );
    
    // Reset session timer
    _resetSessionTimer();
  }
  
  void _endSession() {
    if (_sessionId != null && _sessionStart != null) {
      final duration = DateTime.now().difference(_sessionStart!);
      
      // Track session end
      trackEvent(
        eventType: EventType.session.name,
        eventName: 'session_end',
        properties: {
          'duration': duration.inSeconds,
        },
      );
    }
    
    _sessionId = null;
    _sessionStart = null;
    _sessionTimer?.cancel();
  }
  
  void _resetSessionTimer() {
    _sessionTimer?.cancel();
    _sessionTimer = Timer(_sessionTimeout, () {
      _endSession();
    });
  }
  
  void _startUploadTimer() {
    _uploadTimer?.cancel();
    _uploadTimer = Timer.periodic(_uploadInterval, (_) {
      _uploadEvents();
    });
  }
  
  void _stopUploadTimer() {
    _uploadTimer?.cancel();
    _uploadTimer = null;
  }
  
  Future<void> _uploadEvents() async {
    if (_eventQueue.isEmpty) return;
    
    final eventsToUpload = List<AnalyticsEvent>.from(_eventQueue);
    _eventQueue.clear();
    
    try {
      final authToken = await _authService.getAuthToken();
      
      final response = await _dio.post(
        '${Environment.apiUrl}/analytics/events',
        data: {
          'events': eventsToUpload.map((e) => e.toJson()).toList(),
        },
        options: Options(
          headers: {'Authorization': 'Bearer $authToken'},
        ),
      );
      
      if (response.statusCode == 200) {
        // Mark events as synced in database
        for (final event in eventsToUpload) {
          await _markEventSynced(event.id);
        }
      } else {
        // Re-add to queue for retry
        _eventQueue.insertAll(0, eventsToUpload);
      }
    } catch (e) {
      // Re-add to queue for retry
      _eventQueue.insertAll(0, eventsToUpload);
      debugPrint('Failed to upload analytics events: $e');
    }
  }
  
  Future<void> _saveEvent(AnalyticsEvent event) async {
    await _database.into(_database.analyticsEvents).insert(
      AnalyticsEventsCompanion.insert(
        id: event.id,
        userId: event.userId,
        eventType: event.eventType,
        eventName: event.eventName,
        properties: Value(event.properties != null 
            ? Uri.encodeComponent(event.properties.toString())
            : null),
        timestamp: event.timestamp,
      ),
    );
  }
  
  Future<void> _markEventSynced(String eventId) async {
    await (_database.update(_database.analyticsEvents)
      ..where((tbl) => tbl.id.equals(eventId)))
      .write(const AnalyticsEventsCompanion(
        synced: Value(true),
      ));
  }
  
  Future<void> _loadSettings() async {
    final prefs = await SharedPreferences.getInstance();
    _analyticsEnabled = prefs.getBool('analytics_enabled') ?? false;
    _crashReportingEnabled = prefs.getBool('crash_reporting_enabled') ?? false;
  }
  
  Future<void> _saveSettings() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool('analytics_enabled', _analyticsEnabled);
    await prefs.setBool('crash_reporting_enabled', _crashReportingEnabled);
  }
  
  void dispose() {
    _endSession();
    _stopUploadTimer();
    flush(); // Upload remaining events
  }
}

/// Analytics event
class AnalyticsEvent {
  final String id;
  final String userId;
  final String? sessionId;
  final String eventType;
  final String eventName;
  final Map<String, dynamic>? properties;
  final DateTime timestamp;
  
  const AnalyticsEvent({
    required this.id,
    required this.userId,
    this.sessionId,
    required this.eventType,
    required this.eventName,
    this.properties,
    required this.timestamp,
  });
  
  Map<String, dynamic> toJson() => {
    'id': id,
    'userId': userId,
    if (sessionId != null) 'sessionId': sessionId,
    'eventType': eventType,
    'eventName': eventName,
    if (properties != null) 'properties': properties,
    'timestamp': timestamp.toIso8601String(),
  };
}

/// Event types
enum EventType {
  screenView,
  action,
  timing,
  error,
  session,
  custom,
}

/// Analytics summary
class AnalyticsSummary {
  final int totalEvents;
  final int uniqueUsers;
  final int totalSessions;
  final double avgSessionDuration;
  final Map<String, int> eventCounts;
  final Map<String, int> screenViews;
  final List<PopularAction> popularActions;
  final Map<String, dynamic> demographics;
  
  const AnalyticsSummary({
    required this.totalEvents,
    required this.uniqueUsers,
    required this.totalSessions,
    required this.avgSessionDuration,
    required this.eventCounts,
    required this.screenViews,
    required this.popularActions,
    required this.demographics,
  });
  
  factory AnalyticsSummary.fromJson(Map<String, dynamic> json) {
    return AnalyticsSummary(
      totalEvents: json['totalEvents'],
      uniqueUsers: json['uniqueUsers'],
      totalSessions: json['totalSessions'],
      avgSessionDuration: json['avgSessionDuration'].toDouble(),
      eventCounts: Map<String, int>.from(json['eventCounts']),
      screenViews: Map<String, int>.from(json['screenViews']),
      popularActions: (json['popularActions'] as List)
          .map((a) => PopularAction.fromJson(a))
          .toList(),
      demographics: json['demographics'],
    );
  }
}

/// Popular action
class PopularAction {
  final String action;
  final int count;
  final double percentage;
  
  const PopularAction({
    required this.action,
    required this.count,
    required this.percentage,
  });
  
  factory PopularAction.fromJson(Map<String, dynamic> json) {
    return PopularAction(
      action: json['action'],
      count: json['count'],
      percentage: json['percentage'].toDouble(),
    );
  }
}

/// User behavior insights
class UserBehaviorInsights {
  final String userId;
  final Map<String, dynamic> preferences;
  final List<String> favoriteCategories;
  final List<String> favoriteColors;
  final Map<String, int> activityByHour;
  final Map<String, int> activityByDay;
  final double engagementScore;
  final List<String> recommendations;
  
  const UserBehaviorInsights({
    required this.userId,
    required this.preferences,
    required this.favoriteCategories,
    required this.favoriteColors,
    required this.activityByHour,
    required this.activityByDay,
    required this.engagementScore,
    required this.recommendations,
  });
  
  factory UserBehaviorInsights.fromJson(Map<String, dynamic> json) {
    return UserBehaviorInsights(
      userId: json['userId'],
      preferences: json['preferences'],
      favoriteCategories: List<String>.from(json['favoriteCategories']),
      favoriteColors: List<String>.from(json['favoriteColors']),
      activityByHour: Map<String, int>.from(json['activityByHour']),
      activityByDay: Map<String, int>.from(json['activityByDay']),
      engagementScore: json['engagementScore'].toDouble(),
      recommendations: List<String>.from(json['recommendations']),
    );
  }
}