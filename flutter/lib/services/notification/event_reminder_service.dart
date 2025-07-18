import 'package:flutter/material.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:koutu/services/notification/push_notification_service.dart';
import 'package:koutu/services/recommendation/recommendation_engine.dart';
import 'package:koutu/data/datasources/local/database/app_database.dart';
import 'package:dartz/dartz.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'dart:async';
import 'dart:convert';

/// Service for event-based styling reminders
class EventReminderService {
  final PushNotificationService _notificationService;
  final RecommendationEngine _recommendationEngine;
  final AppDatabase _database;
  
  // Settings
  EventReminderSettings _settings = const EventReminderSettings();
  
  // Active reminders
  final Map<String, Timer> _activeTimers = {};
  final Map<String, EventReminder> _activeReminders = {};
  
  EventReminderService({
    required PushNotificationService notificationService,
    required RecommendationEngine recommendationEngine,
    required AppDatabase database,
  })  : _notificationService = notificationService,
        _recommendationEngine = recommendationEngine,
        _database = database;
  
  /// Initialize event reminder service
  Future<void> initialize() async {
    await _loadSettings();
    await _loadActiveReminders();
    
    if (_settings.enabled) {
      _scheduleAllReminders();
    }
  }
  
  /// Create event reminder
  Future<Either<Failure, EventReminder>> createEventReminder({
    required String title,
    required DateTime eventDateTime,
    required String eventType,
    String? location,
    String? notes,
    String? dressCode,
    List<String>? preferredColors,
    ReminderTiming reminderTiming = ReminderTiming.oneHourBefore,
  }) async {
    try {
      final reminder = EventReminder(
        id: DateTime.now().millisecondsSinceEpoch.toString(),
        title: title,
        eventDateTime: eventDateTime,
        eventType: eventType,
        location: location,
        notes: notes,
        dressCode: dressCode,
        preferredColors: preferredColors,
        reminderTiming: reminderTiming,
        isActive: true,
        createdAt: DateTime.now(),
      );
      
      // Save to database
      await _saveReminder(reminder);
      
      // Schedule notification
      _scheduleReminder(reminder);
      
      // Add to active reminders
      _activeReminders[reminder.id] = reminder;
      
      return Right(reminder);
    } catch (e) {
      return Left(DatabaseFailure('Failed to create reminder: $e'));
    }
  }
  
  /// Update event reminder
  Future<Either<Failure, EventReminder>> updateEventReminder({
    required String reminderId,
    String? title,
    DateTime? eventDateTime,
    String? eventType,
    String? location,
    String? notes,
    String? dressCode,
    List<String>? preferredColors,
    ReminderTiming? reminderTiming,
    bool? isActive,
  }) async {
    try {
      final existingReminder = _activeReminders[reminderId];
      if (existingReminder == null) {
        return Left(DatabaseFailure('Reminder not found'));
      }
      
      final updatedReminder = existingReminder.copyWith(
        title: title,
        eventDateTime: eventDateTime,
        eventType: eventType,
        location: location,
        notes: notes,
        dressCode: dressCode,
        preferredColors: preferredColors,
        reminderTiming: reminderTiming,
        isActive: isActive,
      );
      
      // Update in database
      await _updateReminderInDb(updatedReminder);
      
      // Reschedule if needed
      _cancelReminder(reminderId);
      if (updatedReminder.isActive) {
        _scheduleReminder(updatedReminder);
      }
      
      // Update active reminders
      _activeReminders[reminderId] = updatedReminder;
      
      return Right(updatedReminder);
    } catch (e) {
      return Left(DatabaseFailure('Failed to update reminder: $e'));
    }
  }
  
  /// Delete event reminder
  Future<Either<Failure, void>> deleteEventReminder(String reminderId) async {
    try {
      // Cancel scheduled notification
      _cancelReminder(reminderId);
      
      // Remove from database
      await _deleteReminderFromDb(reminderId);
      
      // Remove from active reminders
      _activeReminders.remove(reminderId);
      
      return const Right(null);
    } catch (e) {
      return Left(DatabaseFailure('Failed to delete reminder: $e'));
    }
  }
  
  /// Get all event reminders
  Future<Either<Failure, List<EventReminder>>> getEventReminders({
    bool activeOnly = false,
  }) async {
    try {
      final reminders = activeOnly
          ? _activeReminders.values.where((r) => r.isActive).toList()
          : _activeReminders.values.toList();
      
      // Sort by event date
      reminders.sort((a, b) => a.eventDateTime.compareTo(b.eventDateTime));
      
      return Right(reminders);
    } catch (e) {
      return Left(DatabaseFailure('Failed to get reminders: $e'));
    }
  }
  
  /// Get upcoming events
  Future<Either<Failure, List<EventReminder>>> getUpcomingEvents({
    int days = 7,
  }) async {
    try {
      final now = DateTime.now();
      final endDate = now.add(Duration(days: days));
      
      final upcomingEvents = _activeReminders.values
          .where((reminder) =>
              reminder.isActive &&
              reminder.eventDateTime.isAfter(now) &&
              reminder.eventDateTime.isBefore(endDate))
          .toList();
      
      upcomingEvents.sort((a, b) => a.eventDateTime.compareTo(b.eventDateTime));
      
      return Right(upcomingEvents);
    } catch (e) {
      return Left(DatabaseFailure('Failed to get upcoming events: $e'));
    }
  }
  
  /// Update settings
  Future<Either<Failure, void>> updateSettings(
    EventReminderSettings settings,
  ) async {
    try {
      _settings = settings;
      await _saveSettings();
      
      // Reschedule all reminders if needed
      _cancelAllReminders();
      if (settings.enabled) {
        _scheduleAllReminders();
      }
      
      return const Right(null);
    } catch (e) {
      return Left(ServerFailure('Failed to update settings: $e'));
    }
  }
  
  /// Get current settings
  EventReminderSettings getSettings() => _settings;
  
  // Private methods
  
  void _scheduleReminder(EventReminder reminder) {
    if (!reminder.isActive || !_settings.enabled) return;
    
    final now = DateTime.now();
    final reminderTime = _calculateReminderTime(
      reminder.eventDateTime,
      reminder.reminderTiming,
    );
    
    if (reminderTime.isBefore(now)) return;
    
    final duration = reminderTime.difference(now);
    
    _activeTimers[reminder.id] = Timer(duration, () async {
      await _sendEventReminder(reminder);
      _activeTimers.remove(reminder.id);
    });
  }
  
  void _scheduleAllReminders() {
    for (final reminder in _activeReminders.values) {
      if (reminder.isActive) {
        _scheduleReminder(reminder);
      }
    }
  }
  
  void _cancelReminder(String reminderId) {
    _activeTimers[reminderId]?.cancel();
    _activeTimers.remove(reminderId);
  }
  
  void _cancelAllReminders() {
    for (final timer in _activeTimers.values) {
      timer.cancel();
    }
    _activeTimers.clear();
  }
  
  DateTime _calculateReminderTime(
    DateTime eventDateTime,
    ReminderTiming timing,
  ) {
    switch (timing) {
      case ReminderTiming.tenMinutesBefore:
        return eventDateTime.subtract(const Duration(minutes: 10));
      case ReminderTiming.thirtyMinutesBefore:
        return eventDateTime.subtract(const Duration(minutes: 30));
      case ReminderTiming.oneHourBefore:
        return eventDateTime.subtract(const Duration(hours: 1));
      case ReminderTiming.twoHoursBefore:
        return eventDateTime.subtract(const Duration(hours: 2));
      case ReminderTiming.oneDayBefore:
        return eventDateTime.subtract(const Duration(days: 1));
      case ReminderTiming.twoDaysBefore:
        return eventDateTime.subtract(const Duration(days: 2));
      case ReminderTiming.oneWeekBefore:
        return eventDateTime.subtract(const Duration(days: 7));
    }
  }
  
  Future<void> _sendEventReminder(EventReminder reminder) async {
    // Get outfit recommendations
    final context = RecommendationContext(
      occasion: reminder.eventType,
      colorPreference: reminder.preferredColors?.firstOrNull,
    );
    
    final recommendationsResult = await _recommendationEngine.getOutfitRecommendations(
      context: context,
      limit: 3,
    );
    
    final recommendations = recommendationsResult.fold(
      (failure) => <OutfitRecommendation>[],
      (recs) => recs,
    );
    
    // Create notification
    final timeUntilEvent = reminder.eventDateTime.difference(DateTime.now());
    String timeText;
    
    if (timeUntilEvent.inDays > 0) {
      timeText = 'in ${timeUntilEvent.inDays} day${timeUntilEvent.inDays > 1 ? "s" : ""}';
    } else if (timeUntilEvent.inHours > 0) {
      timeText = 'in ${timeUntilEvent.inHours} hour${timeUntilEvent.inHours > 1 ? "s" : ""}';
    } else {
      timeText = 'in ${timeUntilEvent.inMinutes} minutes';
    }
    
    final title = '${reminder.title} $timeText';
    var body = 'Time to prepare your outfit!';
    
    if (reminder.dressCode != null) {
      body += ' Dress code: ${reminder.dressCode}';
    }
    
    await _notificationService.sendOutfitSuggestion(
      title: title,
      body: body,
      data: {
        'type': 'event_reminder',
        'reminderId': reminder.id,
        'eventType': reminder.eventType,
        'recommendationIds': recommendations.map((r) => r.id).toList(),
      },
    );
  }
  
  Future<void> _saveReminder(EventReminder reminder) async {
    // In a real app, save to database
    await _saveActiveReminders();
  }
  
  Future<void> _updateReminderInDb(EventReminder reminder) async {
    // In a real app, update in database
    await _saveActiveReminders();
  }
  
  Future<void> _deleteReminderFromDb(String reminderId) async {
    // In a real app, delete from database
    await _saveActiveReminders();
  }
  
  Future<void> _loadActiveReminders() async {
    final prefs = await SharedPreferences.getInstance();
    final remindersJson = prefs.getString('event_reminders');
    
    if (remindersJson != null) {
      final List<dynamic> remindersList = json.decode(remindersJson);
      for (final reminderJson in remindersList) {
        final reminder = EventReminder.fromJson(reminderJson);
        _activeReminders[reminder.id] = reminder;
      }
    }
  }
  
  Future<void> _saveActiveReminders() async {
    final prefs = await SharedPreferences.getInstance();
    final remindersList = _activeReminders.values
        .map((reminder) => reminder.toJson())
        .toList();
    await prefs.setString('event_reminders', json.encode(remindersList));
  }
  
  Future<void> _loadSettings() async {
    final prefs = await SharedPreferences.getInstance();
    final settingsJson = prefs.getString('event_reminder_settings');
    
    if (settingsJson != null) {
      _settings = EventReminderSettings.fromJson(json.decode(settingsJson));
    }
  }
  
  Future<void> _saveSettings() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(
      'event_reminder_settings',
      json.encode(_settings.toJson()),
    );
  }
  
  void dispose() {
    _cancelAllReminders();
  }
}

/// Event reminder model
class EventReminder {
  final String id;
  final String title;
  final DateTime eventDateTime;
  final String eventType;
  final String? location;
  final String? notes;
  final String? dressCode;
  final List<String>? preferredColors;
  final ReminderTiming reminderTiming;
  final bool isActive;
  final DateTime createdAt;
  
  const EventReminder({
    required this.id,
    required this.title,
    required this.eventDateTime,
    required this.eventType,
    this.location,
    this.notes,
    this.dressCode,
    this.preferredColors,
    required this.reminderTiming,
    required this.isActive,
    required this.createdAt,
  });
  
  Map<String, dynamic> toJson() => {
    'id': id,
    'title': title,
    'eventDateTime': eventDateTime.toIso8601String(),
    'eventType': eventType,
    'location': location,
    'notes': notes,
    'dressCode': dressCode,
    'preferredColors': preferredColors,
    'reminderTiming': reminderTiming.name,
    'isActive': isActive,
    'createdAt': createdAt.toIso8601String(),
  };
  
  factory EventReminder.fromJson(Map<String, dynamic> json) {
    return EventReminder(
      id: json['id'],
      title: json['title'],
      eventDateTime: DateTime.parse(json['eventDateTime']),
      eventType: json['eventType'],
      location: json['location'],
      notes: json['notes'],
      dressCode: json['dressCode'],
      preferredColors: json['preferredColors'] != null
          ? List<String>.from(json['preferredColors'])
          : null,
      reminderTiming: ReminderTiming.values.firstWhere(
        (t) => t.name == json['reminderTiming'],
        orElse: () => ReminderTiming.oneHourBefore,
      ),
      isActive: json['isActive'] ?? true,
      createdAt: DateTime.parse(json['createdAt']),
    );
  }
  
  EventReminder copyWith({
    String? title,
    DateTime? eventDateTime,
    String? eventType,
    String? location,
    String? notes,
    String? dressCode,
    List<String>? preferredColors,
    ReminderTiming? reminderTiming,
    bool? isActive,
  }) {
    return EventReminder(
      id: id,
      title: title ?? this.title,
      eventDateTime: eventDateTime ?? this.eventDateTime,
      eventType: eventType ?? this.eventType,
      location: location ?? this.location,
      notes: notes ?? this.notes,
      dressCode: dressCode ?? this.dressCode,
      preferredColors: preferredColors ?? this.preferredColors,
      reminderTiming: reminderTiming ?? this.reminderTiming,
      isActive: isActive ?? this.isActive,
      createdAt: createdAt,
    );
  }
}

/// Reminder timing options
enum ReminderTiming {
  tenMinutesBefore,
  thirtyMinutesBefore,
  oneHourBefore,
  twoHoursBefore,
  oneDayBefore,
  twoDaysBefore,
  oneWeekBefore,
}

/// Event reminder settings
class EventReminderSettings {
  final bool enabled;
  final bool includeRecommendations;
  final bool notifyForAllEvents;
  final List<String> enabledEventTypes;
  
  const EventReminderSettings({
    this.enabled = true,
    this.includeRecommendations = true,
    this.notifyForAllEvents = true,
    this.enabledEventTypes = const [
      'Work',
      'Party',
      'Date',
      'Wedding',
      'Interview',
      'Meeting',
      'Formal',
      'Casual',
    ],
  });
  
  Map<String, dynamic> toJson() => {
    'enabled': enabled,
    'includeRecommendations': includeRecommendations,
    'notifyForAllEvents': notifyForAllEvents,
    'enabledEventTypes': enabledEventTypes,
  };
  
  factory EventReminderSettings.fromJson(Map<String, dynamic> json) {
    return EventReminderSettings(
      enabled: json['enabled'] ?? true,
      includeRecommendations: json['includeRecommendations'] ?? true,
      notifyForAllEvents: json['notifyForAllEvents'] ?? true,
      enabledEventTypes: json['enabledEventTypes'] != null
          ? List<String>.from(json['enabledEventTypes'])
          : const [],
    );
  }
  
  EventReminderSettings copyWith({
    bool? enabled,
    bool? includeRecommendations,
    bool? notifyForAllEvents,
    List<String>? enabledEventTypes,
  }) {
    return EventReminderSettings(
      enabled: enabled ?? this.enabled,
      includeRecommendations: includeRecommendations ?? this.includeRecommendations,
      notifyForAllEvents: notifyForAllEvents ?? this.notifyForAllEvents,
      enabledEventTypes: enabledEventTypes ?? this.enabledEventTypes,
    );
  }
}