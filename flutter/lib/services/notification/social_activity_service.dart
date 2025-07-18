import 'package:flutter/material.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:koutu/services/notification/push_notification_service.dart';
import 'package:koutu/services/social/social_service.dart';
import 'package:koutu/services/analytics/analytics_service.dart';
import 'package:koutu/data/datasources/local/database/app_database.dart';
import 'package:dartz/dartz.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'dart:async';
import 'dart:convert';

/// Service for social activity notifications
class SocialActivityService {
  final PushNotificationService _notificationService;
  final SocialService _socialService;
  final AnalyticsService _analyticsService;
  final AppDatabase _database;
  
  // Settings
  SocialActivitySettings _settings = const SocialActivitySettings();
  
  // Activity tracking
  final Map<String, SocialActivity> _pendingActivities = {};
  final Map<String, DateTime> _lastNotificationTime = {};
  final Map<String, List<SocialActivity>> _activityBatches = {};
  
  // Timers
  Timer? _batchTimer;
  Timer? _summaryTimer;
  
  // Constants
  static const Duration _batchInterval = Duration(minutes: 5);
  static const Duration _summaryInterval = Duration(hours: 12);
  static const Duration _notificationCooldown = Duration(minutes: 30);
  
  SocialActivityService({
    required PushNotificationService notificationService,
    required SocialService socialService,
    required AnalyticsService analyticsService,
    required AppDatabase database,
  })  : _notificationService = notificationService,
        _socialService = socialService,
        _analyticsService = analyticsService,
        _database = database;
  
  /// Initialize social activity service
  Future<void> initialize() async {
    await _loadSettings();
    await _loadPendingActivities();
    
    if (_settings.enabled) {
      _startActivityMonitoring();
    }
  }
  
  /// Handle new social activity
  Future<Either<Failure, void>> handleActivity({
    required SocialActivityType type,
    required String fromUserId,
    required String fromUsername,
    String? fromUserAvatar,
    required String targetId,
    String? targetType,
    String? message,
    Map<String, dynamic>? metadata,
  }) async {
    try {
      if (!_settings.enabled) {
        return const Right(null);
      }
      
      // Check if this activity type is enabled
      if (!_isActivityTypeEnabled(type)) {
        return const Right(null);
      }
      
      final activity = SocialActivity(
        id: DateTime.now().millisecondsSinceEpoch.toString(),
        type: type,
        fromUserId: fromUserId,
        fromUsername: fromUsername,
        fromUserAvatar: fromUserAvatar,
        targetId: targetId,
        targetType: targetType,
        message: message,
        metadata: metadata,
        createdAt: DateTime.now(),
        isRead: false,
      );
      
      // Track activity
      await _analyticsService.trackEvent(
        eventType: 'social_activity',
        eventName: type.name,
        properties: {
          'fromUserId': fromUserId,
          'targetId': targetId,
          'targetType': targetType ?? 'unknown',
        },
      );
      
      // Check notification strategy
      if (_settings.notificationStrategy == NotificationStrategy.instant) {
        await _sendInstantNotification(activity);
      } else {
        _addToBatch(activity);
      }
      
      // Save activity
      _pendingActivities[activity.id] = activity;
      await _savePendingActivities();
      
      return const Right(null);
    } catch (e) {
      return Left(ServerFailure('Failed to handle activity: $e'));
    }
  }
  
  /// Get activity summary
  Future<Either<Failure, ActivitySummary>> getActivitySummary({
    Duration duration = const Duration(days: 1),
  }) async {
    try {
      final cutoffTime = DateTime.now().subtract(duration);
      final recentActivities = _pendingActivities.values
          .where((activity) => activity.createdAt.isAfter(cutoffTime))
          .toList();
      
      // Count by type
      final activityCounts = <SocialActivityType, int>{};
      for (final activity in recentActivities) {
        activityCounts[activity.type] = (activityCounts[activity.type] ?? 0) + 1;
      }
      
      // Get top contributors
      final contributorCounts = <String, int>{};
      for (final activity in recentActivities) {
        final key = '${activity.fromUserId}:${activity.fromUsername}';
        contributorCounts[key] = (contributorCounts[key] ?? 0) + 1;
      }
      
      final topContributors = contributorCounts.entries
          .map((e) {
            final parts = e.key.split(':');
            return TopContributor(
              userId: parts[0],
              username: parts[1],
              activityCount: e.value,
            );
          })
          .toList()
        ..sort((a, b) => b.activityCount.compareTo(a.activityCount));
      
      return Right(ActivitySummary(
        totalActivities: recentActivities.length,
        activityCounts: activityCounts,
        topContributors: topContributors.take(5).toList(),
        periodStart: cutoffTime,
        periodEnd: DateTime.now(),
      ));
    } catch (e) {
      return Left(DatabaseFailure('Failed to get activity summary: $e'));
    }
  }
  
  /// Mark activities as read
  Future<Either<Failure, void>> markActivitiesAsRead(
    List<String> activityIds,
  ) async {
    try {
      for (final id in activityIds) {
        final activity = _pendingActivities[id];
        if (activity != null) {
          _pendingActivities[id] = activity.copyWith(isRead: true);
        }
      }
      
      await _savePendingActivities();
      return const Right(null);
    } catch (e) {
      return Left(DatabaseFailure('Failed to mark activities as read: $e'));
    }
  }
  
  /// Clear old activities
  Future<Either<Failure, void>> clearOldActivities({
    Duration retention = const Duration(days: 30),
  }) async {
    try {
      final cutoffTime = DateTime.now().subtract(retention);
      
      _pendingActivities.removeWhere(
        (_, activity) => activity.createdAt.isBefore(cutoffTime),
      );
      
      await _savePendingActivities();
      return const Right(null);
    } catch (e) {
      return Left(DatabaseFailure('Failed to clear old activities: $e'));
    }
  }
  
  /// Update settings
  Future<Either<Failure, void>> updateSettings(
    SocialActivitySettings settings,
  ) async {
    try {
      _settings = settings;
      await _saveSettings();
      
      // Restart monitoring if needed
      _batchTimer?.cancel();
      _summaryTimer?.cancel();
      
      if (settings.enabled) {
        _startActivityMonitoring();
      }
      
      return const Right(null);
    } catch (e) {
      return Left(ServerFailure('Failed to update settings: $e'));
    }
  }
  
  /// Get current settings
  SocialActivitySettings getSettings() => _settings;
  
  /// Get pending activities
  List<SocialActivity> getPendingActivities({
    bool unreadOnly = false,
  }) {
    final activities = _pendingActivities.values.toList();
    
    if (unreadOnly) {
      return activities.where((a) => !a.isRead).toList()
        ..sort((a, b) => b.createdAt.compareTo(a.createdAt));
    }
    
    return activities..sort((a, b) => b.createdAt.compareTo(a.createdAt));
  }
  
  // Private methods
  
  void _startActivityMonitoring() {
    // Batch processing timer
    if (_settings.notificationStrategy == NotificationStrategy.batched) {
      _batchTimer = Timer.periodic(_batchInterval, (_) {
        _processBatchedActivities();
      });
    }
    
    // Daily summary timer
    if (_settings.dailySummary) {
      final now = DateTime.now();
      final summaryTime = DateTime(
        now.year,
        now.month,
        now.day,
        _settings.summaryTime.hour,
        _settings.summaryTime.minute,
      );
      
      var nextSummary = summaryTime;
      if (now.isAfter(summaryTime)) {
        nextSummary = summaryTime.add(const Duration(days: 1));
      }
      
      final duration = nextSummary.difference(now);
      
      Timer(duration, () {
        _sendDailySummary();
        
        // Schedule recurring daily summaries
        _summaryTimer = Timer.periodic(
          const Duration(days: 1),
          (_) => _sendDailySummary(),
        );
      });
    }
  }
  
  bool _isActivityTypeEnabled(SocialActivityType type) {
    switch (type) {
      case SocialActivityType.like:
        return _settings.likeNotifications;
      case SocialActivityType.comment:
        return _settings.commentNotifications;
      case SocialActivityType.follow:
        return _settings.followNotifications;
      case SocialActivityType.share:
        return _settings.shareNotifications;
      case SocialActivityType.mention:
        return _settings.mentionNotifications;
      case SocialActivityType.outfitCopy:
        return _settings.outfitCopyNotifications;
    }
  }
  
  Future<void> _sendInstantNotification(SocialActivity activity) async {
    // Check cooldown
    final lastTime = _lastNotificationTime[activity.fromUserId];
    if (lastTime != null &&
        DateTime.now().difference(lastTime) < _notificationCooldown) {
      // Add to batch instead
      _addToBatch(activity);
      return;
    }
    
    final title = _getNotificationTitle(activity);
    final body = _getNotificationBody(activity);
    
    final result = await _notificationService.sendSocialNotification(
      title: title,
      body: body,
      imageUrl: activity.fromUserAvatar,
      data: {
        'type': 'social_activity',
        'activityType': activity.type.name,
        'activityId': activity.id,
        'fromUserId': activity.fromUserId,
        'targetId': activity.targetId,
        'targetType': activity.targetType ?? '',
      },
    );
    
    result.fold(
      (failure) => debugPrint('Failed to send notification: ${failure.message}'),
      (_) => null,
    );
    
    _lastNotificationTime[activity.fromUserId] = DateTime.now();
  }
  
  void _addToBatch(SocialActivity activity) {
    final batchKey = activity.type.name;
    _activityBatches[batchKey] ??= [];
    _activityBatches[batchKey]!.add(activity);
  }
  
  Future<void> _processBatchedActivities() async {
    if (_activityBatches.isEmpty) return;
    
    for (final entry in _activityBatches.entries) {
      final type = SocialActivityType.values.firstWhere(
        (t) => t.name == entry.key,
      );
      final activities = entry.value;
      
      if (activities.isEmpty) continue;
      
      // Group by user
      final userGroups = <String, List<SocialActivity>>{};
      for (final activity in activities) {
        userGroups[activity.fromUserId] ??= [];
        userGroups[activity.fromUserId]!.add(activity);
      }
      
      // Send batched notification
      String title;
      String body;
      
      if (userGroups.length == 1 && activities.length == 1) {
        // Single activity - send as instant
        await _sendInstantNotification(activities.first);
      } else if (userGroups.length == 1) {
        // Multiple activities from same user
        final user = activities.first.fromUsername;
        title = _getBatchedTitle(type, activities.length, user);
        body = _getBatchedBody(type, activities.length);
      } else {
        // Multiple users
        title = _getBatchedTitle(type, activities.length);
        body = _getMultiUserBatchedBody(userGroups);
      }
      
      final result = await _notificationService.sendSocialNotification(
        title: title,
        body: body,
        data: {
          'type': 'social_activity_batch',
          'activityType': type.name,
          'activityCount': activities.length,
          'activityIds': activities.map((a) => a.id).toList(),
        },
      );
      
      result.fold(
        (failure) => debugPrint('Failed to send batch notification: ${failure.message}'),
        (_) => null,
      );
    }
    
    // Clear batches
    _activityBatches.clear();
  }
  
  Future<void> _sendDailySummary() async {
    final summaryResult = await getActivitySummary();
    
    summaryResult.fold(
      (failure) => null,
      (summary) async {
        if (summary.totalActivities == 0) return;
        
        final title = 'Your Daily Activity Summary 📊';
        final body = _generateSummaryBody(summary);
        
        final result = await _notificationService.sendSocialNotification(
          title: title,
          body: body,
          data: {
            'type': 'daily_summary',
            'totalActivities': summary.totalActivities,
            'periodStart': summary.periodStart.toIso8601String(),
            'periodEnd': summary.periodEnd.toIso8601String(),
          },
        );
        
        result.fold(
          (failure) => debugPrint('Failed to send daily summary: ${failure.message}'),
          (_) => null,
        );
      },
    );
  }
  
  String _getNotificationTitle(SocialActivity activity) {
    switch (activity.type) {
      case SocialActivityType.like:
        return '${activity.fromUsername} liked your outfit';
      case SocialActivityType.comment:
        return '${activity.fromUsername} commented on your outfit';
      case SocialActivityType.follow:
        return '${activity.fromUsername} started following you';
      case SocialActivityType.share:
        return '${activity.fromUsername} shared your outfit';
      case SocialActivityType.mention:
        return '${activity.fromUsername} mentioned you';
      case SocialActivityType.outfitCopy:
        return '${activity.fromUsername} saved your outfit';
    }
  }
  
  String _getNotificationBody(SocialActivity activity) {
    if (activity.message != null) {
      return activity.message!;
    }
    
    switch (activity.type) {
      case SocialActivityType.like:
        return 'Your outfit is getting attention!';
      case SocialActivityType.comment:
        return 'Check out what they said';
      case SocialActivityType.follow:
        return 'You have a new follower';
      case SocialActivityType.share:
        return 'Your style is inspiring others';
      case SocialActivityType.mention:
        return 'You were mentioned in a post';
      case SocialActivityType.outfitCopy:
        return 'Someone loves your style!';
    }
  }
  
  String _getBatchedTitle(
    SocialActivityType type,
    int count, [
    String? username,
  ]) {
    if (username != null) {
      switch (type) {
        case SocialActivityType.like:
          return '$username liked $count of your outfits';
        case SocialActivityType.comment:
          return '$username left $count comments';
        default:
          return '$count new ${type.name} activities';
      }
    }
    
    switch (type) {
      case SocialActivityType.like:
        return '$count new likes';
      case SocialActivityType.comment:
        return '$count new comments';
      case SocialActivityType.follow:
        return '$count new followers';
      case SocialActivityType.share:
        return '$count new shares';
      case SocialActivityType.mention:
        return '$count new mentions';
      case SocialActivityType.outfitCopy:
        return '$count outfits saved';
    }
  }
  
  String _getBatchedBody(SocialActivityType type, int count) {
    switch (type) {
      case SocialActivityType.like:
        return 'Your outfits are popular!';
      case SocialActivityType.comment:
        return 'Check out the conversations';
      case SocialActivityType.follow:
        return 'Your style is attracting followers';
      case SocialActivityType.share:
        return 'Your outfits are being shared';
      case SocialActivityType.mention:
        return 'You\'re part of the conversation';
      case SocialActivityType.outfitCopy:
        return 'Your style is inspiring others';
    }
  }
  
  String _getMultiUserBatchedBody(Map<String, List<SocialActivity>> userGroups) {
    final userCount = userGroups.length;
    final topUsers = userGroups.keys.take(3).toList();
    
    if (userCount <= 3) {
      final usernames = userGroups.entries
          .map((e) => e.value.first.fromUsername)
          .join(', ');
      return usernames;
    } else {
      final firstTwo = userGroups.entries
          .take(2)
          .map((e) => e.value.first.fromUsername)
          .join(', ');
      return '$firstTwo and ${userCount - 2} others';
    }
  }
  
  String _generateSummaryBody(ActivitySummary summary) {
    final parts = <String>[];
    
    // Total activities
    parts.add('${summary.totalActivities} total activities');
    
    // Top activity types
    final topTypes = summary.activityCounts.entries.toList()
      ..sort((a, b) => b.value.compareTo(a.value));
    
    if (topTypes.isNotEmpty) {
      final topType = topTypes.first;
      parts.add('${topType.value} ${topType.key.name}s');
    }
    
    // Top contributor
    if (summary.topContributors.isNotEmpty) {
      final topContributor = summary.topContributors.first;
      parts.add('${topContributor.username} was most active');
    }
    
    return parts.join(' • ');
  }
  
  Future<void> _loadSettings() async {
    final prefs = await SharedPreferences.getInstance();
    final settingsJson = prefs.getString('social_activity_settings');
    
    if (settingsJson != null) {
      _settings = SocialActivitySettings.fromJson(json.decode(settingsJson));
    }
  }
  
  Future<void> _saveSettings() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(
      'social_activity_settings',
      json.encode(_settings.toJson()),
    );
  }
  
  Future<void> _loadPendingActivities() async {
    final prefs = await SharedPreferences.getInstance();
    final activitiesJson = prefs.getString('pending_social_activities');
    
    if (activitiesJson != null) {
      final Map<String, dynamic> activitiesMap = json.decode(activitiesJson);
      activitiesMap.forEach((key, value) {
        _pendingActivities[key] = SocialActivity.fromJson(value);
      });
    }
  }
  
  Future<void> _savePendingActivities() async {
    final prefs = await SharedPreferences.getInstance();
    final activitiesMap = <String, dynamic>{};
    
    _pendingActivities.forEach((key, value) {
      activitiesMap[key] = value.toJson();
    });
    
    await prefs.setString(
      'pending_social_activities',
      json.encode(activitiesMap),
    );
  }
  
  void dispose() {
    _batchTimer?.cancel();
    _summaryTimer?.cancel();
  }
}

/// Social activity settings
class SocialActivitySettings {
  final bool enabled;
  final NotificationStrategy notificationStrategy;
  final bool likeNotifications;
  final bool commentNotifications;
  final bool followNotifications;
  final bool shareNotifications;
  final bool mentionNotifications;
  final bool outfitCopyNotifications;
  final bool dailySummary;
  final TimeOfDay summaryTime;
  
  const SocialActivitySettings({
    this.enabled = true,
    this.notificationStrategy = NotificationStrategy.smart,
    this.likeNotifications = true,
    this.commentNotifications = true,
    this.followNotifications = true,
    this.shareNotifications = true,
    this.mentionNotifications = true,
    this.outfitCopyNotifications = true,
    this.dailySummary = true,
    this.summaryTime = const TimeOfDay(hour: 20, minute: 0),
  });
  
  Map<String, dynamic> toJson() => {
    'enabled': enabled,
    'notificationStrategy': notificationStrategy.name,
    'likeNotifications': likeNotifications,
    'commentNotifications': commentNotifications,
    'followNotifications': followNotifications,
    'shareNotifications': shareNotifications,
    'mentionNotifications': mentionNotifications,
    'outfitCopyNotifications': outfitCopyNotifications,
    'dailySummary': dailySummary,
    'summaryTimeHour': summaryTime.hour,
    'summaryTimeMinute': summaryTime.minute,
  };
  
  factory SocialActivitySettings.fromJson(Map<String, dynamic> json) {
    return SocialActivitySettings(
      enabled: json['enabled'] ?? true,
      notificationStrategy: NotificationStrategy.values.firstWhere(
        (s) => s.name == json['notificationStrategy'],
        orElse: () => NotificationStrategy.smart,
      ),
      likeNotifications: json['likeNotifications'] ?? true,
      commentNotifications: json['commentNotifications'] ?? true,
      followNotifications: json['followNotifications'] ?? true,
      shareNotifications: json['shareNotifications'] ?? true,
      mentionNotifications: json['mentionNotifications'] ?? true,
      outfitCopyNotifications: json['outfitCopyNotifications'] ?? true,
      dailySummary: json['dailySummary'] ?? true,
      summaryTime: TimeOfDay(
        hour: json['summaryTimeHour'] ?? 20,
        minute: json['summaryTimeMinute'] ?? 0,
      ),
    );
  }
  
  SocialActivitySettings copyWith({
    bool? enabled,
    NotificationStrategy? notificationStrategy,
    bool? likeNotifications,
    bool? commentNotifications,
    bool? followNotifications,
    bool? shareNotifications,
    bool? mentionNotifications,
    bool? outfitCopyNotifications,
    bool? dailySummary,
    TimeOfDay? summaryTime,
  }) {
    return SocialActivitySettings(
      enabled: enabled ?? this.enabled,
      notificationStrategy: notificationStrategy ?? this.notificationStrategy,
      likeNotifications: likeNotifications ?? this.likeNotifications,
      commentNotifications: commentNotifications ?? this.commentNotifications,
      followNotifications: followNotifications ?? this.followNotifications,
      shareNotifications: shareNotifications ?? this.shareNotifications,
      mentionNotifications: mentionNotifications ?? this.mentionNotifications,
      outfitCopyNotifications: outfitCopyNotifications ?? this.outfitCopyNotifications,
      dailySummary: dailySummary ?? this.dailySummary,
      summaryTime: summaryTime ?? this.summaryTime,
    );
  }
}

/// Social activity model
class SocialActivity {
  final String id;
  final SocialActivityType type;
  final String fromUserId;
  final String fromUsername;
  final String? fromUserAvatar;
  final String targetId;
  final String? targetType;
  final String? message;
  final Map<String, dynamic>? metadata;
  final DateTime createdAt;
  final bool isRead;
  
  const SocialActivity({
    required this.id,
    required this.type,
    required this.fromUserId,
    required this.fromUsername,
    this.fromUserAvatar,
    required this.targetId,
    this.targetType,
    this.message,
    this.metadata,
    required this.createdAt,
    required this.isRead,
  });
  
  Map<String, dynamic> toJson() => {
    'id': id,
    'type': type.name,
    'fromUserId': fromUserId,
    'fromUsername': fromUsername,
    'fromUserAvatar': fromUserAvatar,
    'targetId': targetId,
    'targetType': targetType,
    'message': message,
    'metadata': metadata,
    'createdAt': createdAt.toIso8601String(),
    'isRead': isRead,
  };
  
  factory SocialActivity.fromJson(Map<String, dynamic> json) {
    return SocialActivity(
      id: json['id'],
      type: SocialActivityType.values.firstWhere(
        (t) => t.name == json['type'],
      ),
      fromUserId: json['fromUserId'],
      fromUsername: json['fromUsername'],
      fromUserAvatar: json['fromUserAvatar'],
      targetId: json['targetId'],
      targetType: json['targetType'],
      message: json['message'],
      metadata: json['metadata'],
      createdAt: DateTime.parse(json['createdAt']),
      isRead: json['isRead'] ?? false,
    );
  }
  
  SocialActivity copyWith({
    bool? isRead,
  }) {
    return SocialActivity(
      id: id,
      type: type,
      fromUserId: fromUserId,
      fromUsername: fromUsername,
      fromUserAvatar: fromUserAvatar,
      targetId: targetId,
      targetType: targetType,
      message: message,
      metadata: metadata,
      createdAt: createdAt,
      isRead: isRead ?? this.isRead,
    );
  }
}

/// Activity summary
class ActivitySummary {
  final int totalActivities;
  final Map<SocialActivityType, int> activityCounts;
  final List<TopContributor> topContributors;
  final DateTime periodStart;
  final DateTime periodEnd;
  
  const ActivitySummary({
    required this.totalActivities,
    required this.activityCounts,
    required this.topContributors,
    required this.periodStart,
    required this.periodEnd,
  });
}

/// Top contributor
class TopContributor {
  final String userId;
  final String username;
  final int activityCount;
  
  const TopContributor({
    required this.userId,
    required this.username,
    required this.activityCount,
  });
}

/// Social activity types
enum SocialActivityType {
  like,
  comment,
  follow,
  share,
  mention,
  outfitCopy,
}

/// Notification strategy
enum NotificationStrategy {
  instant,
  batched,
  smart,
}