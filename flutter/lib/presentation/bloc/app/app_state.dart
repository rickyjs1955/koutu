import 'package:freezed_annotation/freezed_annotation.dart';
import 'package:flutter/material.dart';
import 'package:koutu/data/models/settings/app_settings.dart';
import 'package:koutu/presentation/bloc/app/app_event.dart';

part 'app_state.freezed.dart';

@freezed
class AppState with _$AppState {
  const AppState._();

  const factory AppState.initial() = _Initial;
  
  const factory AppState.loading() = _Loading;
  
  const factory AppState.ready({
    required ThemeMode themeMode,
    required String language,
    required bool isConnected,
    required bool isFirstTime,
    required bool isOfflineMode,
    required bool isDebugMode,
    required AppSettings settings,
    required int badgeCount,
    @Default(false) bool isSyncing,
    @Default(false) bool isOnboardingComplete,
    DateTime? lastSyncTime,
    String? snackbarMessage,
    SnackbarType? snackbarType,
    String? dialogTitle,
    String? dialogMessage,
    DialogType? dialogType,
    String? errorMessage,
    String? pendingDeepLink,
    @Default([]) List<String> permissionRequests,
    @Default({}) Map<String, dynamic> analytics,
  }) = AppReady;
  
  const factory AppState.error(
    String message,
    AppSettings settings,
  ) = AppError;

  // Helper getters
  bool get isLoading => maybeMap(
    loading: (_) => true,
    orElse: () => false,
  );
  
  bool get isReady => maybeMap(
    ready: (_) => true,
    orElse: () => false,
  );
  
  bool get isError => maybeMap(
    error: (_) => true,
    orElse: () => false,
  );
  
  bool get isInitial => maybeMap(
    initial: (_) => true,
    orElse: () => false,
  );
  
  String? get errorMessage => maybeMap(
    error: (state) => state.message,
    ready: (state) => state.errorMessage,
    orElse: () => null,
  );
  
  AppSettings? get settings => maybeMap(
    ready: (state) => state.settings,
    error: (state) => state.settings,
    orElse: () => null,
  );
  
  ThemeMode get themeMode => maybeMap(
    ready: (state) => state.themeMode,
    orElse: () => ThemeMode.system,
  );
  
  String get language => maybeMap(
    ready: (state) => state.language,
    orElse: () => 'en',
  );
  
  bool get isConnected => maybeMap(
    ready: (state) => state.isConnected,
    orElse: () => false,
  );
  
  bool get isFirstTime => maybeMap(
    ready: (state) => state.isFirstTime,
    orElse: () => true,
  );
  
  bool get isOfflineMode => maybeMap(
    ready: (state) => state.isOfflineMode,
    orElse: () => false,
  );
  
  bool get isDebugMode => maybeMap(
    ready: (state) => state.isDebugMode,
    orElse: () => false,
  );
  
  bool get isSyncing => maybeMap(
    ready: (state) => state.isSyncing,
    orElse: () => false,
  );
  
  int get badgeCount => maybeMap(
    ready: (state) => state.badgeCount,
    orElse: () => 0,
  );
  
  DateTime? get lastSyncTime => maybeMap(
    ready: (state) => state.lastSyncTime,
    orElse: () => null,
  );
  
  String? get snackbarMessage => maybeMap(
    ready: (state) => state.snackbarMessage,
    orElse: () => null,
  );
  
  SnackbarType? get snackbarType => maybeMap(
    ready: (state) => state.snackbarType,
    orElse: () => null,
  );
  
  String? get dialogTitle => maybeMap(
    ready: (state) => state.dialogTitle,
    orElse: () => null,
  );
  
  String? get dialogMessage => maybeMap(
    ready: (state) => state.dialogMessage,
    orElse: () => null,
  );
  
  DialogType? get dialogType => maybeMap(
    ready: (state) => state.dialogType,
    orElse: () => null,
  );
  
  String? get pendingDeepLink => maybeMap(
    ready: (state) => state.pendingDeepLink,
    orElse: () => null,
  );
  
  List<String> get permissionRequests => maybeMap(
    ready: (state) => state.permissionRequests,
    orElse: () => [],
  );
  
  Map<String, dynamic> get analytics => maybeMap(
    ready: (state) => state.analytics,
    orElse: () => {},
  );
  
  bool get hasSnackbar => snackbarMessage != null;
  
  bool get hasDialog => dialogTitle != null && dialogMessage != null;
  
  bool get hasPendingDeepLink => pendingDeepLink != null;
  
  bool get hasPermissionRequests => permissionRequests.isNotEmpty;
  
  bool get shouldShowOnboarding => isFirstTime && isReady;
  
  bool get canSync => isConnected && !isOfflineMode && !isSyncing;
  
  String get syncStatusText {
    if (isSyncing) return 'Syncing...';
    if (isOfflineMode) return 'Offline mode';
    if (!isConnected) return 'No connection';
    if (lastSyncTime != null) {
      final now = DateTime.now();
      final difference = now.difference(lastSyncTime!);
      if (difference.inMinutes < 1) return 'Just synced';
      if (difference.inMinutes < 60) return '${difference.inMinutes}m ago';
      if (difference.inHours < 24) return '${difference.inHours}h ago';
      return '${difference.inDays}d ago';
    }
    return 'Never synced';
  }
  
  Color get connectionStatusColor {
    if (isOfflineMode) return Colors.orange;
    if (!isConnected) return Colors.red;
    if (isSyncing) return Colors.blue;
    return Colors.green;
  }
  
  IconData get connectionStatusIcon {
    if (isOfflineMode) return Icons.cloud_off;
    if (!isConnected) return Icons.wifi_off;
    if (isSyncing) return Icons.sync;
    return Icons.cloud_done;
  }
}