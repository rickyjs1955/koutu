import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:koutu/services/notification/push_notification_service.dart';
import 'package:koutu/services/auth/auth_service.dart';
import 'package:koutu/services/session/session_manager.dart';

/// Provider for push notification service
final pushNotificationServiceProvider = Provider<PushNotificationService>((ref) {
  final authService = ref.watch(authServiceProvider);
  final sessionManager = ref.watch(sessionManagerProvider);
  
  final notificationService = PushNotificationService(
    authService: authService,
    sessionManager: sessionManager,
  );
  
  // Initialize on creation
  notificationService.initialize();
  
  return notificationService;
});

/// Provider for notification settings
final notificationSettingsProvider = Provider<NotificationSettings>((ref) {
  final service = ref.watch(pushNotificationServiceProvider);
  return service.getSettings();
});

/// Notifier for updating notification settings
class NotificationSettingsNotifier extends StateNotifier<NotificationSettings> {
  final PushNotificationService _service;
  
  NotificationSettingsNotifier(this._service) 
      : super(_service.getSettings());
  
  Future<void> updateSettings(NotificationSettings settings) async {
    final result = await _service.updateSettings(settings);
    result.fold(
      (failure) => null, // Handle error
      (_) => state = settings,
    );
  }
  
  Future<void> toggleDailyReminder(bool enabled) async {
    final newSettings = state.copyWith(dailyReminder: enabled);
    await updateSettings(newSettings);
  }
  
  Future<void> setReminderTime(TimeOfDay time) async {
    final newSettings = state.copyWith(reminderTime: time);
    await updateSettings(newSettings);
  }
  
  Future<void> toggleOutfitSuggestions(bool enabled) async {
    final newSettings = state.copyWith(outfitSuggestions: enabled);
    await updateSettings(newSettings);
  }
  
  Future<void> toggleWeatherAlerts(bool enabled) async {
    final newSettings = state.copyWith(weatherAlerts: enabled);
    await updateSettings(newSettings);
  }
  
  Future<void> toggleSocialNotifications(bool enabled) async {
    final newSettings = state.copyWith(socialNotifications: enabled);
    await updateSettings(newSettings);
  }
  
  Future<void> togglePromotions(bool enabled) async {
    final newSettings = state.copyWith(promotions: enabled);
    await updateSettings(newSettings);
  }
}

/// Provider for notification settings notifier
final notificationSettingsNotifierProvider = 
    StateNotifierProvider<NotificationSettingsNotifier, NotificationSettings>((ref) {
  final service = ref.watch(pushNotificationServiceProvider);
  return NotificationSettingsNotifier(service);
});