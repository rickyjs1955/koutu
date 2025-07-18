import 'package:flutter/foundation.dart';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';
import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:koutu/services/auth/auth_service.dart';
import 'package:koutu/services/session/session_manager.dart';
import 'package:dartz/dartz.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'dart:convert';
import 'dart:io';

/// Service for managing push notifications
class PushNotificationService {
  final FirebaseMessaging _messaging = FirebaseMessaging.instance;
  final FlutterLocalNotificationsPlugin _localNotifications = 
      FlutterLocalNotificationsPlugin();
  final AuthService _authService;
  final SessionManager _sessionManager;
  
  // Notification channels
  static const String _channelIdDefault = 'koutu_default';
  static const String _channelIdOutfit = 'koutu_outfit';
  static const String _channelIdSocial = 'koutu_social';
  static const String _channelIdReminder = 'koutu_reminder';
  
  // Notification settings
  NotificationSettings _settings = const NotificationSettings();
  
  PushNotificationService({
    required AuthService authService,
    required SessionManager sessionManager,
  })  : _authService = authService,
        _sessionManager = sessionManager;
  
  /// Initialize push notification service
  Future<Either<Failure, void>> initialize() async {
    try {
      // Request permissions
      final permissionResult = await _requestPermissions();
      if (permissionResult.isLeft()) {
        return permissionResult;
      }
      
      // Initialize local notifications
      await _initializeLocalNotifications();
      
      // Get FCM token
      final token = await _messaging.getToken();
      if (token != null) {
        // Update session with FCM token
        await _sessionManager.updateFCMToken(token);
      }
      
      // Listen for token refresh
      _messaging.onTokenRefresh.listen((newToken) {
        _sessionManager.updateFCMToken(newToken);
      });
      
      // Configure message handlers
      _configureMessageHandlers();
      
      // Load settings
      await _loadSettings();
      
      return const Right(null);
    } catch (e) {
      return Left(ServerFailure('Failed to initialize notifications: $e'));
    }
  }
  
  /// Request notification permissions
  Future<Either<Failure, void>> _requestPermissions() async {
    try {
      final settings = await _messaging.requestPermission(
        alert: true,
        badge: true,
        sound: true,
        provisional: false,
      );
      
      if (settings.authorizationStatus == AuthorizationStatus.authorized) {
        return const Right(null);
      } else if (settings.authorizationStatus == AuthorizationStatus.provisional) {
        return const Right(null);
      } else {
        return Left(PermissionFailure('Notification permission denied'));
      }
    } catch (e) {
      return Left(ServerFailure('Failed to request permissions: $e'));
    }
  }
  
  /// Initialize local notifications
  Future<void> _initializeLocalNotifications() async {
    const androidSettings = AndroidInitializationSettings('@mipmap/ic_launcher');
    const iosSettings = DarwinInitializationSettings(
      requestAlertPermission: true,
      requestBadgePermission: true,
      requestSoundPermission: true,
    );
    
    const initSettings = InitializationSettings(
      android: androidSettings,
      iOS: iosSettings,
    );
    
    await _localNotifications.initialize(
      initSettings,
      onDidReceiveNotificationResponse: _handleNotificationTap,
    );
    
    // Create notification channels for Android
    if (Platform.isAndroid) {
      await _createNotificationChannels();
    }
  }
  
  /// Create Android notification channels
  Future<void> _createNotificationChannels() async {
    const channels = [
      AndroidNotificationChannel(
        _channelIdDefault,
        'Default Notifications',
        description: 'General app notifications',
        importance: Importance.defaultImportance,
      ),
      AndroidNotificationChannel(
        _channelIdOutfit,
        'Outfit Suggestions',
        description: 'Daily outfit recommendations',
        importance: Importance.high,
      ),
      AndroidNotificationChannel(
        _channelIdSocial,
        'Social Updates',
        description: 'Likes, comments, and follows',
        importance: Importance.defaultImportance,
      ),
      AndroidNotificationChannel(
        _channelIdReminder,
        'Reminders',
        description: 'Personal reminders and alerts',
        importance: Importance.high,
      ),
    ];
    
    for (final channel in channels) {
      await _localNotifications
          .resolvePlatformSpecificImplementation<
              AndroidFlutterLocalNotificationsPlugin>()
          ?.createNotificationChannel(channel);
    }
  }
  
  /// Configure message handlers
  void _configureMessageHandlers() {
    // Handle messages when app is in foreground
    FirebaseMessaging.onMessage.listen(_handleForegroundMessage);
    
    // Handle messages when app is in background
    FirebaseMessaging.onMessageOpenedApp.listen(_handleBackgroundMessage);
    
    // Handle initial message if app was launched from notification
    FirebaseMessaging.instance.getInitialMessage().then((message) {
      if (message != null) {
        _handleBackgroundMessage(message);
      }
    });
  }
  
  /// Handle foreground messages
  Future<void> _handleForegroundMessage(RemoteMessage message) async {
    debugPrint('Received foreground message: ${message.messageId}');
    
    // Check if notifications are enabled for this type
    final type = NotificationType.fromString(
      message.data['type'] ?? 'general',
    );
    
    if (!_shouldShowNotification(type)) {
      return;
    }
    
    // Show local notification
    await _showLocalNotification(
      title: message.notification?.title ?? 'Koutu',
      body: message.notification?.body ?? '',
      payload: json.encode(message.data),
      channelId: _getChannelId(type),
    );
  }
  
  /// Handle background messages
  void _handleBackgroundMessage(RemoteMessage message) {
    debugPrint('Handling background message: ${message.messageId}');
    
    // Navigate based on notification type
    final type = message.data['type'];
    final payload = message.data['payload'];
    
    switch (type) {
      case 'outfit_suggestion':
        // Navigate to outfit recommendations
        break;
      case 'social':
        // Navigate to social screen
        break;
      case 'reminder':
        // Navigate to specific screen
        break;
      default:
        // Navigate to home
        break;
    }
  }
  
  /// Handle notification tap
  void _handleNotificationTap(NotificationResponse response) {
    if (response.payload != null) {
      final data = json.decode(response.payload!);
      // Handle navigation based on payload
      debugPrint('Notification tapped with payload: $data');
    }
  }
  
  /// Show local notification
  Future<void> _showLocalNotification({
    required String title,
    required String body,
    String? payload,
    String channelId = _channelIdDefault,
  }) async {
    final androidDetails = AndroidNotificationDetails(
      channelId,
      channelId,
      importance: Importance.high,
      priority: Priority.high,
    );
    
    const iosDetails = DarwinNotificationDetails(
      presentAlert: true,
      presentBadge: true,
      presentSound: true,
    );
    
    final details = NotificationDetails(
      android: androidDetails,
      iOS: iosDetails,
    );
    
    await _localNotifications.show(
      DateTime.now().millisecondsSinceEpoch ~/ 1000,
      title,
      body,
      details,
      payload: payload,
    );
  }
  
  /// Schedule daily outfit reminder
  Future<Either<Failure, void>> scheduleDailyReminder({
    required TimeOfDay time,
  }) async {
    try {
      if (!_settings.dailyReminder) {
        return const Right(null);
      }
      
      // Cancel existing reminder
      await _localNotifications.cancel(1);
      
      // Schedule new reminder
      await _localNotifications.zonedSchedule(
        1,
        'Time to plan your outfit!',
        'Check out today\'s outfit recommendations',
        _nextInstanceOfTime(time),
        const NotificationDetails(
          android: AndroidNotificationDetails(
            _channelIdReminder,
            'Daily Reminder',
            importance: Importance.high,
          ),
          iOS: DarwinNotificationDetails(),
        ),
        androidScheduleMode: AndroidScheduleMode.exactAllowWhileIdle,
        uiLocalNotificationDateInterpretation:
            UILocalNotificationDateInterpretation.absoluteTime,
        matchDateTimeComponents: DateTimeComponents.time,
      );
      
      return const Right(null);
    } catch (e) {
      return Left(ServerFailure('Failed to schedule reminder: $e'));
    }
  }
  
  /// Send outfit suggestion notification
  Future<Either<Failure, void>> sendOutfitSuggestion({
    required String title,
    required String body,
    Map<String, dynamic>? data,
  }) async {
    try {
      if (!_settings.outfitSuggestions) {
        return const Right(null);
      }
      
      await _showLocalNotification(
        title: title,
        body: body,
        payload: json.encode(data ?? {}),
        channelId: _channelIdOutfit,
      );
      
      return const Right(null);
    } catch (e) {
      return Left(ServerFailure('Failed to send outfit suggestion: $e'));
    }
  }
  
  /// Send social notification
  Future<Either<Failure, void>> sendSocialNotification({
    required String title,
    required String body,
    String? imageUrl,
    Map<String, dynamic>? data,
  }) async {
    try {
      if (!_settings.socialNotifications) {
        return const Right(null);
      }
      
      await _showLocalNotification(
        title: title,
        body: body,
        payload: json.encode(data ?? {}),
        channelId: _channelIdSocial,
      );
      
      return const Right(null);
    } catch (e) {
      return Left(ServerFailure('Failed to send social notification: $e'));
    }
  }
  
  /// Update notification settings
  Future<Either<Failure, void>> updateSettings(
    NotificationSettings settings,
  ) async {
    try {
      _settings = settings;
      await _saveSettings();
      
      // Update daily reminder
      if (settings.dailyReminder) {
        await scheduleDailyReminder(time: settings.reminderTime);
      } else {
        await _localNotifications.cancel(1);
      }
      
      return const Right(null);
    } catch (e) {
      return Left(ServerFailure('Failed to update settings: $e'));
    }
  }
  
  /// Get notification settings
  NotificationSettings getSettings() => _settings;
  
  /// Clear all notifications
  Future<void> clearAllNotifications() async {
    await _localNotifications.cancelAll();
  }
  
  /// Get badge count (iOS)
  Future<int> getBadgeCount() async {
    if (Platform.isIOS) {
      // Implementation depends on iOS specific setup
      return 0;
    }
    return 0;
  }
  
  /// Set badge count (iOS)
  Future<void> setBadgeCount(int count) async {
    if (Platform.isIOS) {
      // Implementation depends on iOS specific setup
    }
  }
  
  // Private methods
  
  bool _shouldShowNotification(NotificationType type) {
    switch (type) {
      case NotificationType.outfit:
        return _settings.outfitSuggestions;
      case NotificationType.social:
        return _settings.socialNotifications;
      case NotificationType.weather:
        return _settings.weatherAlerts;
      case NotificationType.promotion:
        return _settings.promotions;
      case NotificationType.general:
        return true;
    }
  }
  
  String _getChannelId(NotificationType type) {
    switch (type) {
      case NotificationType.outfit:
        return _channelIdOutfit;
      case NotificationType.social:
        return _channelIdSocial;
      case NotificationType.weather:
      case NotificationType.general:
        return _channelIdDefault;
      case NotificationType.promotion:
        return _channelIdDefault;
    }
  }
  
  DateTime _nextInstanceOfTime(TimeOfDay time) {
    final now = DateTime.now();
    var scheduledDate = DateTime(
      now.year,
      now.month,
      now.day,
      time.hour,
      time.minute,
    );
    
    if (scheduledDate.isBefore(now)) {
      scheduledDate = scheduledDate.add(const Duration(days: 1));
    }
    
    return scheduledDate;
  }
  
  Future<void> _loadSettings() async {
    final prefs = await SharedPreferences.getInstance();
    final settingsJson = prefs.getString('notification_settings');
    
    if (settingsJson != null) {
      _settings = NotificationSettings.fromJson(json.decode(settingsJson));
    }
  }
  
  Future<void> _saveSettings() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(
      'notification_settings',
      json.encode(_settings.toJson()),
    );
  }
}

/// Notification settings
class NotificationSettings {
  final bool dailyReminder;
  final TimeOfDay reminderTime;
  final bool outfitSuggestions;
  final bool weatherAlerts;
  final bool socialNotifications;
  final bool promotions;
  
  const NotificationSettings({
    this.dailyReminder = true,
    this.reminderTime = const TimeOfDay(hour: 8, minute: 0),
    this.outfitSuggestions = true,
    this.weatherAlerts = true,
    this.socialNotifications = true,
    this.promotions = false,
  });
  
  Map<String, dynamic> toJson() => {
    'dailyReminder': dailyReminder,
    'reminderTime': {
      'hour': reminderTime.hour,
      'minute': reminderTime.minute,
    },
    'outfitSuggestions': outfitSuggestions,
    'weatherAlerts': weatherAlerts,
    'socialNotifications': socialNotifications,
    'promotions': promotions,
  };
  
  factory NotificationSettings.fromJson(Map<String, dynamic> json) {
    return NotificationSettings(
      dailyReminder: json['dailyReminder'] ?? true,
      reminderTime: TimeOfDay(
        hour: json['reminderTime']['hour'] ?? 8,
        minute: json['reminderTime']['minute'] ?? 0,
      ),
      outfitSuggestions: json['outfitSuggestions'] ?? true,
      weatherAlerts: json['weatherAlerts'] ?? true,
      socialNotifications: json['socialNotifications'] ?? true,
      promotions: json['promotions'] ?? false,
    );
  }
  
  NotificationSettings copyWith({
    bool? dailyReminder,
    TimeOfDay? reminderTime,
    bool? outfitSuggestions,
    bool? weatherAlerts,
    bool? socialNotifications,
    bool? promotions,
  }) {
    return NotificationSettings(
      dailyReminder: dailyReminder ?? this.dailyReminder,
      reminderTime: reminderTime ?? this.reminderTime,
      outfitSuggestions: outfitSuggestions ?? this.outfitSuggestions,
      weatherAlerts: weatherAlerts ?? this.weatherAlerts,
      socialNotifications: socialNotifications ?? this.socialNotifications,
      promotions: promotions ?? this.promotions,
    );
  }
}

/// Notification type
enum NotificationType {
  outfit,
  social,
  weather,
  promotion,
  general;
  
  static NotificationType fromString(String type) {
    switch (type) {
      case 'outfit':
        return NotificationType.outfit;
      case 'social':
        return NotificationType.social;
      case 'weather':
        return NotificationType.weather;
      case 'promotion':
        return NotificationType.promotion;
      default:
        return NotificationType.general;
    }
  }
}