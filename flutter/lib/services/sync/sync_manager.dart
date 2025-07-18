import 'package:flutter/foundation.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:koutu/data/datasources/local/database/app_database.dart';
import 'package:koutu/data/models/garment/garment_model.dart';
import 'package:koutu/data/models/wardrobe/wardrobe_model.dart';
import 'package:koutu/data/models/outfit/outfit_model.dart';
import 'package:koutu/services/sync/websocket_service.dart';
import 'package:koutu/services/sync/conflict_resolver.dart';
import 'package:dartz/dartz.dart';
import 'package:drift/drift.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'dart:async';
import 'dart:convert';

/// Manages data synchronization between local and remote storage
class SyncManager {
  final AppDatabase _database;
  final WebSocketService _webSocketService;
  final ConflictResolver _conflictResolver;
  
  // Sync state
  final Map<SyncEntity, DateTime> _lastSyncTimes = {};
  final Map<String, SyncOperation> _pendingSyncOperations = {};
  bool _isSyncing = false;
  
  // Stream controllers
  final _syncStatusController = StreamController<SyncStatus>.broadcast();
  final _syncProgressController = StreamController<SyncProgress>.broadcast();
  
  // Streams
  Stream<SyncStatus> get syncStatus => _syncStatusController.stream;
  Stream<SyncProgress> get syncProgress => _syncProgressController.stream;
  
  // Subscription
  StreamSubscription<SyncEvent>? _syncEventSubscription;
  
  SyncManager({
    required AppDatabase database,
    required WebSocketService webSocketService,
    required ConflictResolver conflictResolver,
  })  : _database = database,
        _webSocketService = webSocketService,
        _conflictResolver = conflictResolver;
  
  /// Initialize sync manager
  Future<void> initialize() async {
    await _loadLastSyncTimes();
    
    // Subscribe to WebSocket sync events
    _syncEventSubscription = _webSocketService.syncEvents.listen(
      _handleSyncEvent,
    );
    
    // Subscribe to connection state changes
    _webSocketService.connectionState.listen((state) {
      if (state == ConnectionState.connected) {
        _performInitialSync();
      }
    });
  }
  
  /// Perform full synchronization
  Future<Either<Failure, void>> performFullSync() async {
    if (_isSyncing) {
      return Left(ServerFailure('Sync already in progress'));
    }
    
    _isSyncing = true;
    _updateSyncStatus(SyncStatus.syncing);
    
    try {
      // Sync each entity type
      final entities = [
        SyncEntity.user,
        SyncEntity.wardrobe,
        SyncEntity.garment,
        SyncEntity.outfit,
        SyncEntity.image,
      ];
      
      for (var i = 0; i < entities.length; i++) {
        _updateProgress(
          current: i,
          total: entities.length,
          message: 'Syncing ${entities[i].name}...',
        );
        
        await _syncEntity(entities[i]);
      }
      
      await _saveLastSyncTimes();
      _updateSyncStatus(SyncStatus.completed);
      
      return const Right(null);
    } catch (e) {
      _updateSyncStatus(SyncStatus.error);
      return Left(ServerFailure('Sync failed: $e'));
    } finally {
      _isSyncing = false;
    }
  }
  
  /// Sync specific entity
  Future<Either<Failure, void>> syncEntity(SyncEntity entity) async {
    if (_isSyncing) {
      return Left(ServerFailure('Sync already in progress'));
    }
    
    _isSyncing = true;
    _updateSyncStatus(SyncStatus.syncing);
    
    try {
      await _syncEntity(entity);
      await _saveLastSyncTimes();
      _updateSyncStatus(SyncStatus.completed);
      
      return const Right(null);
    } catch (e) {
      _updateSyncStatus(SyncStatus.error);
      return Left(ServerFailure('Sync failed: $e'));
    } finally {
      _isSyncing = false;
    }
  }
  
  /// Queue local change for sync
  Future<void> queueLocalChange({
    required String entityId,
    required SyncEntity entityType,
    required SyncOperation operation,
    Map<String, dynamic>? data,
  }) async {
    final change = LocalChange(
      id: DateTime.now().millisecondsSinceEpoch.toString(),
      entityId: entityId,
      entityType: entityType,
      operation: operation,
      data: data,
      timestamp: DateTime.now(),
      syncStatus: SyncChangeStatus.pending,
    );
    
    // Store in database
    await _database.into(_database.syncQueue).insert(
      SyncQueueCompanion(
        id: Value(change.id),
        entityId: Value(change.entityId),
        entityType: Value(change.entityType.name),
        operation: Value(change.operation.name),
        data: Value(json.encode(change.data)),
        timestamp: Value(change.timestamp),
        syncStatus: Value(change.syncStatus.name),
      ),
    );
    
    // Attempt immediate sync if connected
    if (_webSocketService.currentConnectionState == ConnectionState.connected) {
      _processPendingChanges();
    }
  }
  
  /// Get sync statistics
  Future<SyncStatistics> getSyncStatistics() async {
    final pendingChanges = await (_database.select(_database.syncQueue)
      ..where((tbl) => tbl.syncStatus.equals(SyncChangeStatus.pending.name)))
      .get();
    
    final failedChanges = await (_database.select(_database.syncQueue)
      ..where((tbl) => tbl.syncStatus.equals(SyncChangeStatus.failed.name)))
      .get();
    
    return SyncStatistics(
      pendingChanges: pendingChanges.length,
      failedChanges: failedChanges.length,
      lastSyncTimes: Map.from(_lastSyncTimes),
      isConnected: _webSocketService.currentConnectionState == ConnectionState.connected,
      isSyncing: _isSyncing,
    );
  }
  
  // Private methods
  
  void _handleSyncEvent(SyncEvent event) async {
    try {
      switch (event.operation) {
        case SyncOperation.create:
          await _handleRemoteCreate(event);
          break;
        case SyncOperation.update:
          await _handleRemoteUpdate(event);
          break;
        case SyncOperation.delete:
          await _handleRemoteDelete(event);
          break;
        case SyncOperation.batch:
          await _handleRemoteBatch(event);
          break;
      }
    } catch (e) {
      debugPrint('Error handling sync event: $e');
    }
  }
  
  Future<void> _handleRemoteCreate(SyncEvent event) async {
    final entityType = SyncEntity.values.firstWhere(
      (e) => e.name == event.entityType,
    );
    
    switch (entityType) {
      case SyncEntity.garment:
        final garment = GarmentModel.fromJson(event.data);
        await _createOrUpdateGarment(garment);
        break;
      case SyncEntity.wardrobe:
        final wardrobe = WardrobeModel.fromJson(event.data);
        await _createOrUpdateWardrobe(wardrobe);
        break;
      case SyncEntity.outfit:
        final outfit = OutfitModel.fromJson(event.data);
        await _createOrUpdateOutfit(outfit);
        break;
      default:
        break;
    }
  }
  
  Future<void> _handleRemoteUpdate(SyncEvent event) async {
    final entityType = SyncEntity.values.firstWhere(
      (e) => e.name == event.entityType,
    );
    
    // Check for conflicts
    final localEntity = await _getLocalEntity(event.data['id'], entityType);
    
    if (localEntity != null) {
      final resolution = await _conflictResolver.resolveConflict(
        localData: localEntity,
        remoteData: event.data,
        entityType: entityType,
      );
      
      if (resolution.useRemote) {
        await _handleRemoteCreate(event); // Update uses same logic
      }
    } else {
      await _handleRemoteCreate(event); // Create if doesn't exist
    }
  }
  
  Future<void> _handleRemoteDelete(SyncEvent event) async {
    final entityType = SyncEntity.values.firstWhere(
      (e) => e.name == event.entityType,
    );
    
    final entityId = event.data['id'] as String;
    
    switch (entityType) {
      case SyncEntity.garment:
        await (_database.delete(_database.garments)
          ..where((tbl) => tbl.id.equals(entityId)))
          .go();
        break;
      case SyncEntity.wardrobe:
        await (_database.delete(_database.wardrobes)
          ..where((tbl) => tbl.id.equals(entityId)))
          .go();
        break;
      case SyncEntity.outfit:
        await (_database.delete(_database.outfits)
          ..where((tbl) => tbl.id.equals(entityId)))
          .go();
        break;
      default:
        break;
    }
  }
  
  Future<void> _handleRemoteBatch(SyncEvent event) async {
    final operations = event.data['operations'] as List;
    
    for (final op in operations) {
      final batchEvent = SyncEvent(
        id: event.id,
        type: event.type,
        entityType: op['entityType'],
        operation: SyncOperation.values.firstWhere(
          (o) => o.name == op['operation'],
        ),
        data: op['data'],
        timestamp: event.timestamp,
      );
      
      _handleSyncEvent(batchEvent);
    }
  }
  
  Future<void> _syncEntity(SyncEntity entity) async {
    // Request sync from server
    final lastSync = _lastSyncTimes[entity];
    
    await _webSocketService.requestSync(
      entity: entity,
      lastSyncTime: lastSync,
    );
    
    // Process pending local changes
    await _processPendingChangesForEntity(entity);
    
    // Update last sync time
    _lastSyncTimes[entity] = DateTime.now();
  }
  
  Future<void> _processPendingChanges() async {
    final pendingChanges = await (_database.select(_database.syncQueue)
      ..where((tbl) => tbl.syncStatus.equals(SyncChangeStatus.pending.name))
      ..orderBy([(tbl) => OrderingTerm(expression: tbl.timestamp)]))
      .get();
    
    for (final change in pendingChanges) {
      await _processSingleChange(change);
    }
  }
  
  Future<void> _processPendingChangesForEntity(SyncEntity entity) async {
    final pendingChanges = await (_database.select(_database.syncQueue)
      ..where((tbl) => tbl.entityType.equals(entity.name))
      ..where((tbl) => tbl.syncStatus.equals(SyncChangeStatus.pending.name))
      ..orderBy([(tbl) => OrderingTerm(expression: tbl.timestamp)]))
      .get();
    
    for (final change in pendingChanges) {
      await _processSingleChange(change);
    }
  }
  
  Future<void> _processSingleChange(SyncQueueData change) async {
    try {
      final message = WebSocketMessage(
        type: MessageType.sync,
        data: {
          'entityId': change.entityId,
          'entityType': change.entityType,
          'operation': change.operation,
          'data': json.decode(change.data),
          'timestamp': change.timestamp.toIso8601String(),
        },
      );
      
      final result = await _webSocketService.sendMessage(message);
      
      result.fold(
        (failure) async {
          // Mark as failed
          await (_database.update(_database.syncQueue)
            ..where((tbl) => tbl.id.equals(change.id)))
            .write(SyncQueueCompanion(
              syncStatus: Value(SyncChangeStatus.failed.name),
              retryCount: Value(change.retryCount + 1),
            ));
        },
        (_) async {
          // Mark as synced
          await (_database.update(_database.syncQueue)
            ..where((tbl) => tbl.id.equals(change.id)))
            .write(SyncQueueCompanion(
              syncStatus: Value(SyncChangeStatus.synced.name),
              syncedAt: Value(DateTime.now()),
            ));
        },
      );
    } catch (e) {
      debugPrint('Error processing sync change: $e');
    }
  }
  
  Future<Map<String, dynamic>?> _getLocalEntity(
    String entityId,
    SyncEntity entityType,
  ) async {
    switch (entityType) {
      case SyncEntity.garment:
        final garment = await (_database.select(_database.garments)
          ..where((tbl) => tbl.id.equals(entityId)))
          .getSingleOrNull();
        return garment?.toJson();
        
      case SyncEntity.wardrobe:
        final wardrobe = await (_database.select(_database.wardrobes)
          ..where((tbl) => tbl.id.equals(entityId)))
          .getSingleOrNull();
        return wardrobe?.toJson();
        
      case SyncEntity.outfit:
        final outfit = await (_database.select(_database.outfits)
          ..where((tbl) => tbl.id.equals(entityId)))
          .getSingleOrNull();
        return outfit?.toJson();
        
      default:
        return null;
    }
  }
  
  Future<void> _createOrUpdateGarment(GarmentModel garment) async {
    await _database.into(_database.garments).insertOnConflictUpdate(
      GarmentsCompanion(
        id: Value(garment.id),
        wardrobeId: Value(garment.wardrobeId),
        name: Value(garment.name),
        category: Value(garment.category),
        color: Value(garment.color),
        brand: Value(garment.brand),
        size: Value(garment.size),
        material: Value(garment.material),
        careInstructions: Value(garment.careInstructions.join(',')),
        tags: Value(garment.tags.join(',')),
        purchaseDate: Value(garment.purchaseDate),
        purchasePrice: Value(garment.purchasePrice),
        currentValue: Value(garment.currentValue),
        wearCount: Value(garment.wearCount),
        lastWornDate: Value(garment.lastWornDate),
        season: Value(garment.season),
        notes: Value(garment.notes),
        createdAt: Value(garment.createdAt),
        updatedAt: Value(garment.updatedAt),
      ),
    );
    
    // Sync images
    for (final image in garment.images) {
      await _database.into(_database.images).insertOnConflictUpdate(
        ImagesCompanion(
          id: Value(image.id),
          garmentId: Value(garment.id),
          url: Value(image.url),
          thumbnailUrl: Value(image.thumbnailUrl),
          width: Value(image.width),
          height: Value(image.height),
          size: Value(image.size),
          createdAt: Value(image.createdAt),
        ),
      );
    }
  }
  
  Future<void> _createOrUpdateWardrobe(WardrobeModel wardrobe) async {
    await _database.into(_database.wardrobes).insertOnConflictUpdate(
      WardrobesCompanion(
        id: Value(wardrobe.id),
        userId: Value(wardrobe.userId),
        name: Value(wardrobe.name),
        description: Value(wardrobe.description),
        icon: Value(wardrobe.icon),
        coverImage: Value(wardrobe.coverImage),
        isShared: Value(wardrobe.isShared),
        sharedWith: Value(wardrobe.sharedWith.join(',')),
        defaultView: Value(wardrobe.settings.defaultView),
        sortBy: Value(wardrobe.settings.sortBy),
        groupBy: Value(wardrobe.settings.groupBy),
        showStatistics: Value(wardrobe.settings.showStatistics),
        createdAt: Value(wardrobe.createdAt),
        updatedAt: Value(wardrobe.updatedAt),
      ),
    );
  }
  
  Future<void> _createOrUpdateOutfit(OutfitModel outfit) async {
    await _database.into(_database.outfits).insertOnConflictUpdate(
      OutfitsCompanion(
        id: Value(outfit.id),
        wardrobeId: Value(outfit.wardrobeId),
        name: Value(outfit.name),
        description: Value(outfit.description),
        occasion: Value(outfit.occasion),
        season: Value(outfit.season),
        tags: Value(outfit.tags.join(',')),
        rating: Value(outfit.rating),
        wearCount: Value(outfit.wearCount),
        lastWornDate: Value(outfit.lastWornDate),
        imageUrl: Value(outfit.imageUrl),
        createdAt: Value(outfit.createdAt),
        updatedAt: Value(outfit.updatedAt),
      ),
    );
    
    // Sync outfit garments
    // This would need additional implementation
  }
  
  Future<void> _performInitialSync() async {
    if (!_isSyncing) {
      performFullSync();
    }
  }
  
  Future<void> _loadLastSyncTimes() async {
    final prefs = await SharedPreferences.getInstance();
    
    for (final entity in SyncEntity.values) {
      final timeStr = prefs.getString('last_sync_${entity.name}');
      if (timeStr != null) {
        _lastSyncTimes[entity] = DateTime.parse(timeStr);
      }
    }
  }
  
  Future<void> _saveLastSyncTimes() async {
    final prefs = await SharedPreferences.getInstance();
    
    for (final entry in _lastSyncTimes.entries) {
      await prefs.setString(
        'last_sync_${entry.key.name}',
        entry.value.toIso8601String(),
      );
    }
  }
  
  void _updateSyncStatus(SyncStatus status) {
    _syncStatusController.add(status);
  }
  
  void _updateProgress({
    required int current,
    required int total,
    required String message,
  }) {
    _syncProgressController.add(SyncProgress(
      current: current,
      total: total,
      percentage: current / total,
      message: message,
    ));
  }
  
  void dispose() {
    _syncEventSubscription?.cancel();
    _syncStatusController.close();
    _syncProgressController.close();
  }
}

/// Sync status
enum SyncStatus {
  idle,
  syncing,
  completed,
  error,
}

/// Sync progress
class SyncProgress {
  final int current;
  final int total;
  final double percentage;
  final String message;
  
  const SyncProgress({
    required this.current,
    required this.total,
    required this.percentage,
    required this.message,
  });
}

/// Local change model
class LocalChange {
  final String id;
  final String entityId;
  final SyncEntity entityType;
  final SyncOperation operation;
  final Map<String, dynamic>? data;
  final DateTime timestamp;
  final SyncChangeStatus syncStatus;
  
  const LocalChange({
    required this.id,
    required this.entityId,
    required this.entityType,
    required this.operation,
    this.data,
    required this.timestamp,
    required this.syncStatus,
  });
}

/// Sync change status
enum SyncChangeStatus {
  pending,
  syncing,
  synced,
  failed,
}

/// Sync statistics
class SyncStatistics {
  final int pendingChanges;
  final int failedChanges;
  final Map<SyncEntity, DateTime> lastSyncTimes;
  final bool isConnected;
  final bool isSyncing;
  
  const SyncStatistics({
    required this.pendingChanges,
    required this.failedChanges,
    required this.lastSyncTimes,
    required this.isConnected,
    required this.isSyncing,
  });
}