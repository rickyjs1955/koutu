import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:koutu/services/backup/backup_manager.dart';
import 'package:koutu/services/cloud/cloud_storage_service.dart';
import 'package:koutu/services/auth/auth_service.dart';
import 'package:koutu/data/datasources/local/database/app_database.dart';
import 'package:koutu/core/errors/failures.dart';

/// Provider for backup manager
final backupManagerProvider = Provider<BackupManager>((ref) {
  final database = ref.watch(databaseProvider);
  final cloudStorage = ref.watch(cloudStorageServiceProvider);
  final authService = ref.watch(authServiceProvider);
  
  final backupManager = BackupManager(
    database: database,
    cloudStorage: cloudStorage,
    authService: authService,
  );
  
  // Initialize on creation
  backupManager.initialize();
  
  // Dispose when provider is destroyed
  ref.onDispose(() {
    backupManager.dispose();
  });
  
  return backupManager;
});

/// Provider for backup history
final backupHistoryProvider = FutureProvider<List<BackupRecord>>((ref) async {
  final backupManager = ref.watch(backupManagerProvider);
  final result = await backupManager.getBackupHistory();
  
  return result.fold(
    (failure) => throw failure,
    (history) => history,
  );
});

/// Provider for backup status stream
final backupStatusProvider = StreamProvider<BackupStatus>((ref) {
  final backupManager = ref.watch(backupManagerProvider);
  return backupManager.backupStatus;
});

/// Provider for backup progress stream
final backupProgressProvider = StreamProvider<BackupProgress>((ref) {
  final backupManager = ref.watch(backupManagerProvider);
  return backupManager.backupProgress;
});

/// Provider for cloud storage service
final cloudStorageServiceProvider = Provider<CloudStorageService>((ref) {
  final dio = ref.watch(dioProvider);
  final authService = ref.watch(authServiceProvider);
  
  return CloudStorageService(
    dio: dio,
    authService: authService,
  );
});

/// Provider for storage statistics
final storageStatisticsProvider = FutureProvider<StorageStatistics>((ref) async {
  final cloudStorage = ref.watch(cloudStorageServiceProvider);
  final result = await cloudStorage.getStorageStatistics();
  
  return result.fold(
    (failure) => throw failure,
    (stats) => stats,
  );
});