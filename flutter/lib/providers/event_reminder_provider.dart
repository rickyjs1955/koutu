import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:koutu/services/notification/event_reminder_service.dart';
import 'package:koutu/services/notification/push_notification_service.dart';
import 'package:koutu/services/recommendation/recommendation_engine.dart';
import 'package:koutu/data/datasources/local/database/app_database.dart';

/// Provider for event reminder service
final eventReminderServiceProvider = Provider<EventReminderService>((ref) {
  final notificationService = ref.watch(pushNotificationServiceProvider);
  final recommendationEngine = ref.watch(recommendationEngineProvider);
  final database = ref.watch(databaseProvider);
  
  final eventReminderService = EventReminderService(
    notificationService: notificationService,
    recommendationEngine: recommendationEngine,
    database: database,
  );
  
  // Initialize on creation
  eventReminderService.initialize();
  
  // Dispose when provider is destroyed
  ref.onDispose(() {
    eventReminderService.dispose();
  });
  
  return eventReminderService;
});

/// Provider for all event reminders
final eventRemindersProvider = FutureProvider<List<EventReminder>>((ref) async {
  final service = ref.watch(eventReminderServiceProvider);
  final result = await service.getEventReminders();
  
  return result.fold(
    (failure) => throw failure,
    (reminders) => reminders,
  );
});

/// Provider for active event reminders
final activeEventRemindersProvider = FutureProvider<List<EventReminder>>((ref) async {
  final service = ref.watch(eventReminderServiceProvider);
  final result = await service.getEventReminders(activeOnly: true);
  
  return result.fold(
    (failure) => throw failure,
    (reminders) => reminders,
  );
});

/// Provider for upcoming events
final upcomingEventsProvider = FutureProvider.family<
  List<EventReminder>,
  int
>((ref, days) async {
  final service = ref.watch(eventReminderServiceProvider);
  final result = await service.getUpcomingEvents(days: days);
  
  return result.fold(
    (failure) => throw failure,
    (events) => events,
  );
});

/// Provider for event reminder settings
final eventReminderSettingsProvider = Provider<EventReminderSettings>((ref) {
  final service = ref.watch(eventReminderServiceProvider);
  return service.getSettings();
});