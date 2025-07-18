import 'package:freezed_annotation/freezed_annotation.dart';
import 'package:flutter/material.dart';
import 'package:koutu/data/models/settings/app_settings.dart';

part 'app_event.freezed.dart';

@freezed
class AppEvent with _$AppEvent {
  const factory AppEvent.initialize() = _Initialize;
  
  const factory AppEvent.themeChanged(ThemeMode themeMode) = _ThemeChanged;
  
  const factory AppEvent.languageChanged(String language) = _LanguageChanged;
  
  const factory AppEvent.connectivityChanged(bool isConnected) = _ConnectivityChanged;
  
  const factory AppEvent.syncData() = _SyncData;
  
  const factory AppEvent.clearCache() = _ClearCache;
  
  const factory AppEvent.showSnackbar(
    String message, {
    @Default(SnackbarType.info) SnackbarType type,
  }) = _ShowSnackbar;
  
  const factory AppEvent.hideSnackbar() = _HideSnackbar;
  
  const factory AppEvent.showDialog(
    String title,
    String message, {
    @Default(DialogType.info) DialogType type,
  }) = _ShowDialog;
  
  const factory AppEvent.hideDialog() = _HideDialog;
  
  const factory AppEvent.updateSettings(AppSettings settings) = _UpdateSettings;
  
  const factory AppEvent.resetApp() = _ResetApp;
  
  const factory AppEvent.enableOfflineMode() = _EnableOfflineMode;
  
  const factory AppEvent.disableOfflineMode() = _DisableOfflineMode;
  
  const factory AppEvent.logError(
    String error, {
    StackTrace? stackTrace,
    @Default(false) bool showToUser,
  }) = _LogError;
  
  const factory AppEvent.enableDebugMode() = _EnableDebugMode;
  
  const factory AppEvent.disableDebugMode() = _DisableDebugMode;
  
  const factory AppEvent.updateOnboardingStatus(bool isCompleted) = _UpdateOnboardingStatus;
  
  const factory AppEvent.scheduleBackgroundSync() = _ScheduleBackgroundSync;
  
  const factory AppEvent.cancelBackgroundSync() = _CancelBackgroundSync;
  
  const factory AppEvent.handleDeepLink(String deepLink) = _HandleDeepLink;
  
  const factory AppEvent.updateBadgeCount(int count) = _UpdateBadgeCount;
  
  const factory AppEvent.clearBadgeCount() = _ClearBadgeCount;
  
  const factory AppEvent.requestPermissions(List<String> permissions) = _RequestPermissions;
  
  const factory AppEvent.updateAnalytics(bool enabled) = _UpdateAnalytics;
  
  const factory AppEvent.refreshApp() = _RefreshApp;
}

enum SnackbarType {
  info,
  success,
  warning,
  error,
}

enum DialogType {
  info,
  success,
  warning,
  error,
  confirmation,
}