import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:koutu/services/session/session_manager.dart';
import 'package:koutu/services/auth/auth_service.dart';
import 'package:koutu/services/sync/websocket_service.dart';
import 'package:koutu/data/datasources/local/database/app_database.dart';
import 'package:dio/dio.dart';

/// Provider for session manager
final sessionManagerProvider = Provider<SessionManager>((ref) {
  final database = ref.watch(databaseProvider);
  final authService = ref.watch(authServiceProvider);
  final webSocketService = ref.watch(webSocketServiceProvider);
  final dio = ref.watch(dioProvider);
  
  final sessionManager = SessionManager(
    database: database,
    authService: authService,
    webSocketService: webSocketService,
    dio: dio,
  );
  
  // Initialize on creation
  sessionManager.initialize();
  
  // Dispose when provider is destroyed
  ref.onDispose(() {
    sessionManager.dispose();
  });
  
  return sessionManager;
});

/// Provider for session state stream
final sessionStateProvider = StreamProvider<SessionState>((ref) {
  final sessionManager = ref.watch(sessionManagerProvider);
  return sessionManager.sessionState;
});

/// Provider for active sessions stream
final activeSessionsProvider = StreamProvider<List<SessionInfo>>((ref) {
  final sessionManager = ref.watch(sessionManagerProvider);
  return sessionManager.activeSessions;
});

/// Provider for current session
final currentSessionProvider = Provider<SessionInfo?>((ref) {
  final sessionManager = ref.watch(sessionManagerProvider);
  return sessionManager.getCurrentSession();
});

/// Provider for device limit check
final isDeviceLimitReachedProvider = FutureProvider<bool>((ref) async {
  final sessionManager = ref.watch(sessionManagerProvider);
  final result = await sessionManager.isDeviceLimitReached();
  
  return result.fold(
    (failure) => false,
    (isReached) => isReached,
  );
});

/// Provider for backup needed check
final isBackupNeededProvider = Provider<bool>((ref) {
  final backupManager = ref.watch(backupManagerProvider);
  return backupManager.isBackupNeeded();
});

/// Provider for last backup time
final lastBackupTimeProvider = Provider<DateTime?>((ref) {
  final backupManager = ref.watch(backupManagerProvider);
  return backupManager.getLastBackupTime();
});