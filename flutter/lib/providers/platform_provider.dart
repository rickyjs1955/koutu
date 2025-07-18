import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:koutu/services/platform/ios_widget_service.dart';
import 'package:koutu/services/platform/android_widget_service.dart';
import 'package:koutu/services/platform/wearable_service.dart';
import 'package:koutu/services/platform/voice_assistant_service.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Provider for iOS widget service
final iosWidgetServiceProvider = FutureProvider<IOSWidgetService>((ref) async {
  final preferences = await SharedPreferences.getInstance();
  
  return IOSWidgetService(
    preferences: preferences,
  );
});

/// Provider for Android widget service
final androidWidgetServiceProvider = FutureProvider<AndroidWidgetService>((ref) async {
  final preferences = await SharedPreferences.getInstance();
  
  return AndroidWidgetService(
    preferences: preferences,
  );
});

/// Provider for wearable service
final wearableServiceProvider = FutureProvider<WearableService>((ref) async {
  final preferences = await SharedPreferences.getInstance();
  
  return WearableService(
    preferences: preferences,
  );
});

/// Provider for voice assistant service
final voiceAssistantServiceProvider = FutureProvider<VoiceAssistantService>((ref) async {
  final preferences = await SharedPreferences.getInstance();
  
  return VoiceAssistantService(
    preferences: preferences,
  );
});

/// Provider for iOS widget settings
final iosWidgetSettingsProvider = FutureProvider<IOSWidgetSettings>((ref) async {
  final service = await ref.watch(iosWidgetServiceProvider.future);
  return service.getWidgetSettings();
});

/// Provider for Android widget settings
final androidWidgetSettingsProvider = FutureProvider<AndroidWidgetSettings>((ref) async {
  final service = await ref.watch(androidWidgetServiceProvider.future);
  return service.getWidgetSettings();
});

/// Provider for wearable settings
final wearableSettingsProvider = FutureProvider<WearableSettings>((ref) async {
  final service = await ref.watch(wearableServiceProvider.future);
  return service.getWearableSettings();
});

/// Provider for voice assistant settings
final voiceAssistantSettingsProvider = FutureProvider<VoiceAssistantSettings>((ref) async {
  final service = await ref.watch(voiceAssistantServiceProvider.future);
  return service.getVoiceAssistantSettings();
});

/// Provider for connected wearable devices
final connectedWearableDevicesProvider = FutureProvider<List<WearableDevice>>((ref) async {
  final service = await ref.watch(wearableServiceProvider.future);
  final result = await service.getConnectedDevices();
  
  return result.fold(
    (failure) => [],
    (devices) => devices,
  );
});

/// Provider for available voice shortcuts
final availableVoiceShortcutsProvider = FutureProvider<List<VoiceShortcut>>((ref) async {
  final service = await ref.watch(voiceAssistantServiceProvider.future);
  final result = await service.getAvailableVoiceShortcuts();
  
  return result.fold(
    (failure) => [],
    (shortcuts) => shortcuts,
  );
});

/// Provider for voice assistant capabilities
final voiceAssistantCapabilitiesProvider = FutureProvider<VoiceAssistantCapabilities>((ref) async {
  final service = await ref.watch(voiceAssistantServiceProvider.future);
  final result = await service.getVoiceAssistantCapabilities();
  
  return result.fold(
    (failure) => const VoiceAssistantCapabilities(
      siriAvailable: false,
      googleAssistantAvailable: false,
      customShortcutsSupported: false,
      contextualSuggestionsSupported: false,
      voiceResponseSupported: false,
      hapticFeedbackSupported: false,
      supportedIntents: [],
    ),
    (capabilities) => capabilities,
  );
});

/// Provider for iOS widget availability
final iosWidgetAvailabilityProvider = FutureProvider<bool>((ref) async {
  final service = await ref.watch(iosWidgetServiceProvider.future);
  final result = await service.isWidgetAvailable();
  
  return result.fold(
    (failure) => false,
    (available) => available,
  );
});

/// Provider for Android widget providers
final androidWidgetProvidersProvider = FutureProvider<List<AndroidWidgetProvider>>((ref) async {
  final service = await ref.watch(androidWidgetServiceProvider.future);
  final result = await service.getWidgetProviders();
  
  return result.fold(
    (failure) => [],
    (providers) => providers,
  );
});

/// Provider for active Android widgets
final activeAndroidWidgetsProvider = FutureProvider<List<AndroidActiveWidget>>((ref) async {
  final service = await ref.watch(androidWidgetServiceProvider.future);
  final result = await service.getActiveWidgets();
  
  return result.fold(
    (failure) => [],
    (widgets) => widgets,
  );
});

/// Provider for available iOS widget sizes
final iosWidgetSizesProvider = FutureProvider<List<WidgetSize>>((ref) async {
  final service = await ref.watch(iosWidgetServiceProvider.future);
  final result = await service.getAvailableWidgetSizes();
  
  return result.fold(
    (failure) => [],
    (sizes) => sizes,
  );
});

/// Provider for iOS widget timeline
final iosWidgetTimelineProvider = FutureProvider.family<List<WidgetTimelineEntry>, String>((ref, widgetType) async {
  final service = await ref.watch(iosWidgetServiceProvider.future);
  final result = await service.getWidgetTimeline(widgetType);
  
  return result.fold(
    (failure) => [],
    (timeline) => timeline,
  );
});

/// Provider for wearable battery status
final wearableBatteryStatusProvider = FutureProvider<Map<String, int>>((ref) async {
  final service = await ref.watch(wearableServiceProvider.future);
  final result = await service.getWearableBatteryStatus();
  
  return result.fold(
    (failure) => {},
    (status) => status,
  );
});

/// Provider for voice intent history
final voiceIntentHistoryProvider = FutureProvider<List<VoiceIntentHistoryEntry>>((ref) async {
  final service = await ref.watch(voiceAssistantServiceProvider.future);
  final result = await service.getVoiceIntentHistory();
  
  return result.fold(
    (failure) => [],
    (history) => history,
  );
});

/// Provider for voice assistant test result
final voiceAssistantTestResultProvider = FutureProvider<VoiceAssistantTestResult>((ref) async {
  final service = await ref.watch(voiceAssistantServiceProvider.future);
  final result = await service.testVoiceAssistantIntegration();
  
  return result.fold(
    (failure) => const VoiceAssistantTestResult(
      siriIntegrationWorking: false,
      googleAssistantIntegrationWorking: false,
      shortcutsRegistered: false,
      actionsRegistered: false,
      errors: [],
      warnings: [],
    ),
    (testResult) => testResult,
  );
});

/// State notifier for platform integration status
class PlatformIntegrationStatusNotifier extends StateNotifier<PlatformIntegrationStatus> {
  PlatformIntegrationStatusNotifier() : super(PlatformIntegrationStatus.initializing);
  
  void setInitializing() {
    state = PlatformIntegrationStatus.initializing;
  }
  
  void setReady() {
    state = PlatformIntegrationStatus.ready;
  }
  
  void setError(String error) {
    state = PlatformIntegrationStatus.error;
  }
  
  void setSyncing() {
    state = PlatformIntegrationStatus.syncing;
  }
}

/// Provider for platform integration status
final platformIntegrationStatusProvider = StateNotifierProvider<PlatformIntegrationStatusNotifier, PlatformIntegrationStatus>((ref) {
  return PlatformIntegrationStatusNotifier();
});

/// State notifier for widget sync status
class WidgetSyncStatusNotifier extends StateNotifier<WidgetSyncStatus> {
  WidgetSyncStatusNotifier() : super(WidgetSyncStatus.idle);
  
  void setSyncing() {
    state = WidgetSyncStatus.syncing;
  }
  
  void setSuccess() {
    state = WidgetSyncStatus.success;
  }
  
  void setError(String error) {
    state = WidgetSyncStatus.error;
  }
  
  void setIdle() {
    state = WidgetSyncStatus.idle;
  }
}

/// Provider for widget sync status
final widgetSyncStatusProvider = StateNotifierProvider<WidgetSyncStatusNotifier, WidgetSyncStatus>((ref) {
  return WidgetSyncStatusNotifier();
});

/// State notifier for wearable sync status
class WearableSyncStatusNotifier extends StateNotifier<WearableSyncStatus> {
  WearableSyncStatusNotifier() : super(WearableSyncStatus.idle);
  
  void setSyncing() {
    state = WearableSyncStatus.syncing;
  }
  
  void setSuccess() {
    state = WearableSyncStatus.success;
  }
  
  void setError(String error) {
    state = WearableSyncStatus.error;
  }
  
  void setIdle() {
    state = WearableSyncStatus.idle;
  }
}

/// Provider for wearable sync status
final wearableSyncStatusProvider = StateNotifierProvider<WearableSyncStatusNotifier, WearableSyncStatus>((ref) {
  return WearableSyncStatusNotifier();
});

/// Provider for contextual voice suggestions
final contextualVoiceSuggestionsProvider = FutureProvider.family<List<VoiceContextualSuggestion>, String>((ref, context) async {
  final service = await ref.watch(voiceAssistantServiceProvider.future);
  final result = await service.generateContextualSuggestions(context);
  
  return result.fold(
    (failure) => [],
    (suggestions) => suggestions,
  );
});

// Data classes and enums

enum PlatformIntegrationStatus {
  initializing,
  ready,
  error,
  syncing,
}

enum WidgetSyncStatus {
  idle,
  syncing,
  success,
  error,
}

enum WearableSyncStatus {
  idle,
  syncing,
  success,
  error,
}