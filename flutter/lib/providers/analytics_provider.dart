import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:koutu/services/analytics/analytics_service.dart';
import 'package:koutu/services/auth/auth_service.dart';
import 'package:koutu/data/datasources/local/database/app_database.dart';
import 'package:dio/dio.dart';

/// Provider for analytics service
final analyticsServiceProvider = Provider<AnalyticsService>((ref) {
  final database = ref.watch(databaseProvider);
  final authService = ref.watch(authServiceProvider);
  final dio = ref.watch(dioProvider);
  
  final analyticsService = AnalyticsService(
    database: database,
    authService: authService,
    dio: dio,
  );
  
  // Initialize on creation
  analyticsService.initialize();
  
  // Dispose when provider is destroyed
  ref.onDispose(() {
    analyticsService.dispose();
  });
  
  return analyticsService;
});

/// Provider for analytics settings
final analyticsSettingsProvider = Provider<(bool, bool)>((ref) {
  final service = ref.watch(analyticsServiceProvider);
  return service.getSettings();
});

/// Provider for analytics summary
final analyticsSummaryProvider = FutureProvider.family<
  AnalyticsSummary,
  DateRange?
>((ref, dateRange) async {
  final service = ref.watch(analyticsServiceProvider);
  final result = await service.getAnalyticsSummary(
    startDate: dateRange?.start,
    endDate: dateRange?.end,
  );
  
  return result.fold(
    (failure) => throw failure,
    (summary) => summary,
  );
});

/// Provider for user behavior insights
final userInsightsProvider = FutureProvider<UserBehaviorInsights>((ref) async {
  final service = ref.watch(analyticsServiceProvider);
  final result = await service.getUserInsights();
  
  return result.fold(
    (failure) => throw failure,
    (insights) => insights,
  );
});

/// Notifier for analytics settings
class AnalyticsSettingsNotifier extends StateNotifier<AnalyticsSettings> {
  final AnalyticsService _service;
  
  AnalyticsSettingsNotifier(this._service) : super(
    AnalyticsSettings(
      analyticsEnabled: _service.getSettings().$1,
      crashReportingEnabled: _service.getSettings().$2,
    ),
  );
  
  Future<void> toggleAnalytics(bool enabled) async {
    await _service.updateSettings(
      analyticsEnabled: enabled,
      crashReportingEnabled: state.crashReportingEnabled,
    );
    state = state.copyWith(analyticsEnabled: enabled);
  }
  
  Future<void> toggleCrashReporting(bool enabled) async {
    await _service.updateSettings(
      analyticsEnabled: state.analyticsEnabled,
      crashReportingEnabled: enabled,
    );
    state = state.copyWith(crashReportingEnabled: enabled);
  }
}

/// Provider for analytics settings notifier
final analyticsSettingsNotifierProvider = 
    StateNotifierProvider<AnalyticsSettingsNotifier, AnalyticsSettings>((ref) {
  final service = ref.watch(analyticsServiceProvider);
  return AnalyticsSettingsNotifier(service);
});

/// Analytics settings model
class AnalyticsSettings {
  final bool analyticsEnabled;
  final bool crashReportingEnabled;
  
  const AnalyticsSettings({
    required this.analyticsEnabled,
    required this.crashReportingEnabled,
  });
  
  AnalyticsSettings copyWith({
    bool? analyticsEnabled,
    bool? crashReportingEnabled,
  }) {
    return AnalyticsSettings(
      analyticsEnabled: analyticsEnabled ?? this.analyticsEnabled,
      crashReportingEnabled: crashReportingEnabled ?? this.crashReportingEnabled,
    );
  }
}

/// Date range for analytics
class DateRange {
  final DateTime start;
  final DateTime end;
  
  const DateRange({
    required this.start,
    required this.end,
  });
}