import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:koutu/services/notification/social_activity_service.dart';
import 'package:koutu/services/notification/push_notification_service.dart';
import 'package:koutu/services/social/social_service.dart';
import 'package:koutu/services/analytics/analytics_service.dart';
import 'package:koutu/data/datasources/local/database/app_database.dart';

/// Provider for social service
final socialServiceProvider = Provider<SocialService>((ref) {
  final database = ref.watch(databaseProvider);
  
  return SocialService(
    database: database,
  );
});

/// Provider for social activity service
final socialActivityServiceProvider = Provider<SocialActivityService>((ref) {
  final notificationService = ref.watch(pushNotificationServiceProvider);
  final socialService = ref.watch(socialServiceProvider);
  final analyticsService = ref.watch(analyticsServiceProvider);
  final database = ref.watch(databaseProvider);
  
  final socialActivityService = SocialActivityService(
    notificationService: notificationService,
    socialService: socialService,
    analyticsService: analyticsService,
    database: database,
  );
  
  // Initialize on creation
  socialActivityService.initialize();
  
  // Dispose when provider is destroyed
  ref.onDispose(() {
    socialActivityService.dispose();
  });
  
  return socialActivityService;
});

/// Provider for pending social activities
final pendingSocialActivitiesProvider = Provider<List<SocialActivity>>((ref) {
  final service = ref.watch(socialActivityServiceProvider);
  return service.getPendingActivities();
});

/// Provider for unread social activities
final unreadSocialActivitiesProvider = Provider<List<SocialActivity>>((ref) {
  final service = ref.watch(socialActivityServiceProvider);
  return service.getPendingActivities(unreadOnly: true);
});

/// Provider for activity summary
final activitySummaryProvider = FutureProvider.family<
  ActivitySummary,
  Duration
>((ref, duration) async {
  final service = ref.watch(socialActivityServiceProvider);
  final result = await service.getActivitySummary(duration: duration);
  
  return result.fold(
    (failure) => throw failure,
    (summary) => summary,
  );
});

/// Provider for social activity settings
final socialActivitySettingsProvider = Provider<SocialActivitySettings>((ref) {
  final service = ref.watch(socialActivityServiceProvider);
  return service.getSettings();
});