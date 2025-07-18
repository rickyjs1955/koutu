import 'dart:async';
import 'package:connectivity_plus/connectivity_plus.dart';
import 'package:injectable/injectable.dart';
import 'package:koutu/data/local/database/app_database.dart';
import 'package:koutu/data/local/database/tables/sync_queue_table.dart';
import 'package:koutu/data/local/cache/cache_policy.dart';
import 'package:koutu/data/network/api_client.dart';
import 'package:koutu/core/utils/logger.dart';

@lazySingleton
class OfflineSyncManager {
  final AppDatabase _database;
  final ApiClient _apiClient;
  final CachePolicy _cachePolicy;
  final Connectivity _connectivity;

  Timer? _syncTimer;
  bool _isSyncing = false;
  final _syncStatusController = StreamController<SyncStatus>.broadcast();

  OfflineSyncManager(
    this._database,
    this._apiClient,
    this._cachePolicy,
    this._connectivity,
  );

  Stream<SyncStatus> get syncStatusStream => _syncStatusController.stream;

  /// Initialize offline sync manager
  Future<void> initialize() async {
    // Listen to connectivity changes
    _connectivity.onConnectivityChanged.listen(_onConnectivityChanged);

    // Start periodic sync
    _startPeriodicSync();

    // Check for pending sync items on startup
    await _checkPendingSyncItems();
  }

  /// Start periodic sync
  void _startPeriodicSync() {
    _syncTimer?.cancel();
    _syncTimer = Timer.periodic(CachePolicy.syncInterval, (_) {
      _checkPendingSyncItems();
    });
  }

  /// Handle connectivity changes
  void _onConnectivityChanged(List<ConnectivityResult> result) {
    final hasConnection = result.isNotEmpty && 
        !result.contains(ConnectivityResult.none);
    
    if (hasConnection && !_isSyncing) {
      // Connection restored, sync pending items
      _checkPendingSyncItems();
    }
  }

  /// Check and sync pending items
  Future<void> _checkPendingSyncItems() async {
    if (_isSyncing) return;

    try {
      _isSyncing = true;
      _syncStatusController.add(SyncStatus.inProgress);

      // Get all pending sync items
      final pendingItems = await _database.syncQueueDao.getScheduledSyncItems();
      
      if (pendingItems.isEmpty) {
        _syncStatusController.add(SyncStatus.completed);
        return;
      }

      Logger.info('Syncing ${pendingItems.length} pending items');

      // Process each item
      for (final item in pendingItems) {
        await _processSyncItem(item);
      }

      // Clean up old completed items
      await _database.syncQueueDao.deleteOldCompletedItems(
        const Duration(days: 7),
      );

      _syncStatusController.add(SyncStatus.completed);
    } catch (e) {
      Logger.error('Sync error', error: e);
      _syncStatusController.add(SyncStatus.failed);
    } finally {
      _isSyncing = false;
    }
  }

  /// Process individual sync item
  Future<void> _processSyncItem(SyncQueueData item) async {
    try {
      // Mark as in progress
      await _database.syncQueueDao.markInProgress(item.id);

      // Process based on operation type
      switch (item.operation) {
        case SyncOperation.create:
          await _processCreate(item);
          break;
        case SyncOperation.update:
          await _processUpdate(item);
          break;
        case SyncOperation.delete:
          await _processDelete(item);
          break;
      }

      // Mark as completed
      await _database.syncQueueDao.markCompleted(item.id);
    } catch (e) {
      Logger.error('Failed to sync item ${item.id}', error: e);
      
      // Mark as failed and schedule retry
      await _database.syncQueueDao.markFailed(item.id, e.toString());
      
      // Schedule retry with exponential backoff
      if (item.retryCount < 5) {
        final delay = _database.syncQueueDao.getRetryDelay(item.retryCount);
        await _database.syncQueueDao.scheduleRetry(item.id, delay);
      }
    }
  }

  /// Process create operation
  Future<void> _processCreate(SyncQueueData item) async {
    switch (item.entityType) {
      case 'wardrobe':
        await _apiClient.post('/wardrobes', data: item.payload);
        break;
      case 'garment':
        await _apiClient.post('/garments', data: item.payload);
        break;
      case 'image':
        await _apiClient.post('/images', data: item.payload);
        break;
      default:
        throw Exception('Unknown entity type: ${item.entityType}');
    }
  }

  /// Process update operation
  Future<void> _processUpdate(SyncQueueData item) async {
    switch (item.entityType) {
      case 'wardrobe':
        await _apiClient.put('/wardrobes/${item.entityId}', data: item.payload);
        break;
      case 'garment':
        await _apiClient.put('/garments/${item.entityId}', data: item.payload);
        break;
      case 'image':
        await _apiClient.put('/images/${item.entityId}', data: item.payload);
        break;
      case 'user':
        await _apiClient.put('/users/${item.entityId}', data: item.payload);
        break;
      default:
        throw Exception('Unknown entity type: ${item.entityType}');
    }
  }

  /// Process delete operation
  Future<void> _processDelete(SyncQueueData item) async {
    switch (item.entityType) {
      case 'wardrobe':
        await _apiClient.delete('/wardrobes/${item.entityId}');
        break;
      case 'garment':
        await _apiClient.delete('/garments/${item.entityId}');
        break;
      case 'image':
        await _apiClient.delete('/images/${item.entityId}');
        break;
      default:
        throw Exception('Unknown entity type: ${item.entityType}');
    }
  }

  /// Add operation to sync queue
  Future<void> addToSyncQueue({
    required SyncOperation operation,
    required String entityType,
    required String entityId,
    required Map<String, dynamic> payload,
    String? userId,
    String? wardrobeId,
    String? garmentId,
  }) async {
    await _database.syncQueueDao.addToSyncQueue(
      operation: operation,
      entityType: entityType,
      entityId: entityId,
      payload: payload,
      userId: userId,
      wardrobeId: wardrobeId,
      garmentId: garmentId,
    );
  }

  /// Force sync all pending items
  Future<void> forceSync() async {
    await _checkPendingSyncItems();
  }

  /// Get sync queue statistics
  Future<Map<String, int>> getSyncStatistics() async {
    return await _database.syncQueueDao.getSyncQueueStatistics();
  }

  /// Clear all sync data
  Future<void> clearSyncQueue() async {
    await _database.syncQueueDao.clearSyncQueue();
  }

  /// Dispose resources
  void dispose() {
    _syncTimer?.cancel();
    _syncStatusController.close();
  }
}