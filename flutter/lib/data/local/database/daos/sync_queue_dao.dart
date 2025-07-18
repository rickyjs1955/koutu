import 'package:drift/drift.dart';
import 'package:koutu/data/local/database/app_database.dart';
import 'package:koutu/data/local/database/tables/sync_queue_table.dart';

part 'sync_queue_dao.g.dart';

@DriftAccessor(tables: [SyncQueue])
class SyncQueueDao extends DatabaseAccessor<AppDatabase> with _$SyncQueueDaoMixin {
  SyncQueueDao(AppDatabase db) : super(db);

  /// Get all pending sync items
  Future<List<SyncQueueData>> getPendingSyncItems() async {
    return await (select(syncQueue)
          ..where((s) => s.status.equals(SyncStatus.pending))
          ..orderBy([(s) => OrderingTerm(expression: s.createdAt)]))
        .get();
  }

  /// Get sync items scheduled for now
  Future<List<SyncQueueData>> getScheduledSyncItems() async {
    final now = DateTime.now();
    return await (select(syncQueue)
          ..where((s) =>
              s.status.equals(SyncStatus.pending) &
              (s.scheduledAt.isNull() | s.scheduledAt.isSmallerOrEqualValue(now)))
          ..orderBy([(s) => OrderingTerm(expression: s.createdAt)]))
        .get();
  }

  /// Get failed sync items for retry
  Future<List<SyncQueueData>> getFailedSyncItems(int maxRetries) async {
    return await (select(syncQueue)
          ..where((s) =>
              s.status.equals(SyncStatus.failed) & s.retryCount.isSmallerThanValue(maxRetries))
          ..orderBy([(s) => OrderingTerm(expression: s.retryCount)]))
        .get();
  }

  /// Add item to sync queue
  Future<int> addToSyncQueue({
    required SyncOperation operation,
    required String entityType,
    required String entityId,
    required Map<String, dynamic> payload,
    String? userId,
    String? wardrobeId,
    String? garmentId,
    DateTime? scheduledAt,
  }) async {
    return await into(syncQueue).insert(
      SyncQueueCompanion(
        operation: Value(operation),
        entityType: Value(entityType),
        entityId: Value(entityId),
        userId: Value(userId),
        wardrobeId: Value(wardrobeId),
        garmentId: Value(garmentId),
        payload: Value(payload),
        status: const Value(SyncStatus.pending),
        retryCount: const Value(0),
        createdAt: Value(DateTime.now()),
        updatedAt: Value(DateTime.now()),
        scheduledAt: Value(scheduledAt),
      ),
    );
  }

  /// Update sync item status
  Future<void> updateSyncStatus(
    int id,
    SyncStatus status, {
    String? error,
    int? retryCount,
  }) async {
    await (update(syncQueue)..where((s) => s.id.equals(id))).write(
      SyncQueueCompanion(
        status: Value(status),
        lastError: Value(error),
        retryCount: retryCount != null ? Value(retryCount) : const Value.absent(),
        updatedAt: Value(DateTime.now()),
      ),
    );
  }

  /// Mark sync item as in progress
  Future<void> markInProgress(int id) async {
    await updateSyncStatus(id, SyncStatus.inProgress);
  }

  /// Mark sync item as completed
  Future<void> markCompleted(int id) async {
    await updateSyncStatus(id, SyncStatus.completed);
  }

  /// Mark sync item as failed
  Future<void> markFailed(int id, String error) async {
    final item = await (select(syncQueue)..where((s) => s.id.equals(id))).getSingle();
    await updateSyncStatus(
      id,
      SyncStatus.failed,
      error: error,
      retryCount: item.retryCount + 1,
    );
  }

  /// Schedule retry for failed item
  Future<void> scheduleRetry(int id, Duration delay) async {
    final scheduledAt = DateTime.now().add(delay);
    await (update(syncQueue)..where((s) => s.id.equals(id))).write(
      SyncQueueCompanion(
        status: const Value(SyncStatus.pending),
        scheduledAt: Value(scheduledAt),
        updatedAt: Value(DateTime.now()),
      ),
    );
  }

  /// Delete completed sync items older than specified duration
  Future<void> deleteOldCompletedItems(Duration maxAge) async {
    final cutoffDate = DateTime.now().subtract(maxAge);
    await (delete(syncQueue)
          ..where((s) =>
              s.status.equals(SyncStatus.completed) & s.updatedAt.isSmallerThan(cutoffDate)))
        .go();
  }

  /// Delete specific sync item
  Future<void> deleteSyncItem(int id) async {
    await (delete(syncQueue)..where((s) => s.id.equals(id))).go();
  }

  /// Clear all sync items
  Future<void> clearSyncQueue() async {
    await delete(syncQueue).go();
  }

  /// Get sync queue statistics
  Future<Map<String, int>> getSyncQueueStatistics() async {
    final counts = await customSelect(
      '''
      SELECT 
        status,
        COUNT(*) as count
      FROM sync_queue
      GROUP BY status
      ''',
      readsFrom: {syncQueue},
    ).get();

    final stats = <String, int>{
      'pending': 0,
      'inProgress': 0,
      'completed': 0,
      'failed': 0,
      'total': 0,
    };

    for (final row in counts) {
      final status = row.read<String>('status');
      final count = row.read<int>('count');
      stats[status] = count;
      stats['total'] = stats['total']! + count;
    }

    return stats;
  }

  /// Check if entity has pending sync
  Future<bool> hasPendingSync(String entityType, String entityId) async {
    final count = await (selectOnly(syncQueue)
          ..where(syncQueue.entityType.equals(entityType) &
              syncQueue.entityId.equals(entityId) &
              syncQueue.status.equals(SyncStatus.pending))
          ..addColumns([syncQueue.id.count()]))
        .getSingle();
    return (count.read(syncQueue.id.count()) ?? 0) > 0;
  }

  /// Get retry delay based on retry count (exponential backoff)
  Duration getRetryDelay(int retryCount) {
    final baseDelay = 5; // 5 seconds
    final maxDelay = 300; // 5 minutes
    final delay = baseDelay * (1 << retryCount); // Exponential backoff
    return Duration(seconds: delay.clamp(baseDelay, maxDelay));
  }
}