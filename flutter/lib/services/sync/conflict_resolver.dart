import 'package:flutter/material.dart';
import 'package:koutu/services/sync/websocket_service.dart';

/// Service for resolving sync conflicts between local and remote data
class ConflictResolver {
  // Conflict resolution strategies
  final ConflictResolutionStrategy defaultStrategy;
  final Map<SyncEntity, ConflictResolutionStrategy> entityStrategies;
  
  ConflictResolver({
    this.defaultStrategy = ConflictResolutionStrategy.lastWriteWins,
    this.entityStrategies = const {},
  });
  
  /// Resolve conflict between local and remote data
  Future<ConflictResolution> resolveConflict({
    required Map<String, dynamic> localData,
    required Map<String, dynamic> remoteData,
    required SyncEntity entityType,
  }) async {
    final strategy = entityStrategies[entityType] ?? defaultStrategy;
    
    switch (strategy) {
      case ConflictResolutionStrategy.lastWriteWins:
        return _resolveLastWriteWins(localData, remoteData);
        
      case ConflictResolutionStrategy.remoteWins:
        return ConflictResolution(
          useRemote: true,
          mergedData: remoteData,
          reason: 'Remote data takes precedence',
        );
        
      case ConflictResolutionStrategy.localWins:
        return ConflictResolution(
          useRemote: false,
          mergedData: localData,
          reason: 'Local data takes precedence',
        );
        
      case ConflictResolutionStrategy.merge:
        return _resolveMerge(localData, remoteData, entityType);
        
      case ConflictResolutionStrategy.manual:
        return _resolveManual(localData, remoteData, entityType);
    }
  }
  
  /// Show conflict resolution dialog to user
  Future<ConflictResolution> showConflictDialog({
    required BuildContext context,
    required Map<String, dynamic> localData,
    required Map<String, dynamic> remoteData,
    required SyncEntity entityType,
  }) async {
    final result = await showDialog<ConflictChoice>(
      context: context,
      barrierDismissible: false,
      builder: (context) => ConflictResolutionDialog(
        localData: localData,
        remoteData: remoteData,
        entityType: entityType,
      ),
    );
    
    if (result == null) {
      // Default to remote if dialog dismissed
      return ConflictResolution(
        useRemote: true,
        mergedData: remoteData,
        reason: 'User cancelled - using remote data',
      );
    }
    
    switch (result) {
      case ConflictChoice.keepLocal:
        return ConflictResolution(
          useRemote: false,
          mergedData: localData,
          reason: 'User chose to keep local version',
        );
        
      case ConflictChoice.keepRemote:
        return ConflictResolution(
          useRemote: true,
          mergedData: remoteData,
          reason: 'User chose to keep remote version',
        );
        
      case ConflictChoice.merge:
        final merged = await _showMergeDialog(
          context: context,
          localData: localData,
          remoteData: remoteData,
          entityType: entityType,
        );
        return ConflictResolution(
          useRemote: true,
          mergedData: merged,
          reason: 'User manually merged changes',
        );
    }
  }
  
  // Private methods
  
  ConflictResolution _resolveLastWriteWins(
    Map<String, dynamic> localData,
    Map<String, dynamic> remoteData,
  ) {
    final localUpdated = DateTime.parse(localData['updatedAt'] ?? '');
    final remoteUpdated = DateTime.parse(remoteData['updatedAt'] ?? '');
    
    if (remoteUpdated.isAfter(localUpdated)) {
      return ConflictResolution(
        useRemote: true,
        mergedData: remoteData,
        reason: 'Remote data is newer',
      );
    } else {
      return ConflictResolution(
        useRemote: false,
        mergedData: localData,
        reason: 'Local data is newer',
      );
    }
  }
  
  Future<ConflictResolution> _resolveMerge(
    Map<String, dynamic> localData,
    Map<String, dynamic> remoteData,
    SyncEntity entityType,
  ) async {
    // Automatic merge based on entity type
    final merged = Map<String, dynamic>.from(remoteData);
    
    switch (entityType) {
      case SyncEntity.garment:
        // Merge garment-specific fields
        merged['wearCount'] = _mergeNumericField(
          localData['wearCount'],
          remoteData['wearCount'],
          MergeStrategy.sum,
        );
        
        merged['tags'] = _mergeListField(
          localData['tags'],
          remoteData['tags'],
        );
        
        // Keep most recent wear date
        final localWorn = localData['lastWornDate'] != null 
            ? DateTime.parse(localData['lastWornDate']) 
            : null;
        final remoteWorn = remoteData['lastWornDate'] != null 
            ? DateTime.parse(remoteData['lastWornDate']) 
            : null;
            
        if (localWorn != null && remoteWorn != null) {
          merged['lastWornDate'] = localWorn.isAfter(remoteWorn) 
              ? localData['lastWornDate'] 
              : remoteData['lastWornDate'];
        }
        break;
        
      case SyncEntity.wardrobe:
        // Merge shared users
        merged['sharedWith'] = _mergeListField(
          localData['sharedWith'],
          remoteData['sharedWith'],
        );
        break;
        
      case SyncEntity.outfit:
        // Merge outfit fields
        merged['wearCount'] = _mergeNumericField(
          localData['wearCount'],
          remoteData['wearCount'],
          MergeStrategy.sum,
        );
        
        merged['rating'] = _mergeNumericField(
          localData['rating'],
          remoteData['rating'],
          MergeStrategy.average,
        );
        break;
        
      default:
        // For other entities, use last write wins
        return _resolveLastWriteWins(localData, remoteData);
    }
    
    return ConflictResolution(
      useRemote: true,
      mergedData: merged,
      reason: 'Automatically merged changes',
    );
  }
  
  Future<ConflictResolution> _resolveManual(
    Map<String, dynamic> localData,
    Map<String, dynamic> remoteData,
    SyncEntity entityType,
  ) async {
    // For now, default to last write wins
    // In a real app, this would show a UI for manual resolution
    return _resolveLastWriteWins(localData, remoteData);
  }
  
  dynamic _mergeNumericField(
    dynamic local,
    dynamic remote,
    MergeStrategy strategy,
  ) {
    if (local == null) return remote;
    if (remote == null) return local;
    
    final localNum = local is num ? local : num.tryParse(local.toString()) ?? 0;
    final remoteNum = remote is num ? remote : num.tryParse(remote.toString()) ?? 0;
    
    switch (strategy) {
      case MergeStrategy.sum:
        return localNum + remoteNum;
      case MergeStrategy.average:
        return (localNum + remoteNum) / 2;
      case MergeStrategy.max:
        return localNum > remoteNum ? localNum : remoteNum;
      case MergeStrategy.min:
        return localNum < remoteNum ? localNum : remoteNum;
    }
  }
  
  List<dynamic> _mergeListField(dynamic local, dynamic remote) {
    final localList = local is List ? local : [];
    final remoteList = remote is List ? remote : [];
    
    // Merge unique values
    final merged = <dynamic>{};
    merged.addAll(localList);
    merged.addAll(remoteList);
    
    return merged.toList();
  }
  
  Future<Map<String, dynamic>> _showMergeDialog({
    required BuildContext context,
    required Map<String, dynamic> localData,
    required Map<String, dynamic> remoteData,
    required SyncEntity entityType,
  }) async {
    // In a real implementation, this would show a detailed merge UI
    // For now, we'll do automatic merge
    final resolution = await _resolveMerge(localData, remoteData, entityType);
    return resolution.mergedData;
  }
}

/// Conflict resolution result
class ConflictResolution {
  final bool useRemote;
  final Map<String, dynamic> mergedData;
  final String reason;
  
  const ConflictResolution({
    required this.useRemote,
    required this.mergedData,
    required this.reason,
  });
}

/// Conflict resolution strategies
enum ConflictResolutionStrategy {
  lastWriteWins,
  remoteWins,
  localWins,
  merge,
  manual,
}

/// Merge strategies for numeric fields
enum MergeStrategy {
  sum,
  average,
  max,
  min,
}

/// User choice in conflict dialog
enum ConflictChoice {
  keepLocal,
  keepRemote,
  merge,
}

/// Conflict resolution dialog
class ConflictResolutionDialog extends StatelessWidget {
  final Map<String, dynamic> localData;
  final Map<String, dynamic> remoteData;
  final SyncEntity entityType;
  
  const ConflictResolutionDialog({
    super.key,
    required this.localData,
    required this.remoteData,
    required this.entityType,
  });

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Text('Sync Conflict'),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'A conflict was detected for ${entityType.name}:',
              style: Theme.of(context).textTheme.bodyMedium,
            ),
            const SizedBox(height: 16),
            _buildDataComparison(context),
            const SizedBox(height: 16),
            const Text(
              'Which version would you like to keep?',
              style: TextStyle(fontWeight: FontWeight.bold),
            ),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context, ConflictChoice.keepLocal),
          child: const Text('Keep Local'),
        ),
        TextButton(
          onPressed: () => Navigator.pop(context, ConflictChoice.keepRemote),
          child: const Text('Keep Remote'),
        ),
        ElevatedButton(
          onPressed: () => Navigator.pop(context, ConflictChoice.merge),
          child: const Text('Merge'),
        ),
      ],
    );
  }
  
  Widget _buildDataComparison(BuildContext context) {
    final fields = _getComparableFields();
    
    return Table(
      columnWidths: const {
        0: FlexColumnWidth(2),
        1: FlexColumnWidth(3),
        2: FlexColumnWidth(3),
      },
      border: TableBorder.all(
        color: Theme.of(context).dividerColor,
      ),
      children: [
        TableRow(
          decoration: BoxDecoration(
            color: Theme.of(context).colorScheme.surfaceVariant,
          ),
          children: const [
            Padding(
              padding: EdgeInsets.all(8.0),
              child: Text(
                'Field',
                style: TextStyle(fontWeight: FontWeight.bold),
              ),
            ),
            Padding(
              padding: EdgeInsets.all(8.0),
              child: Text(
                'Local',
                style: TextStyle(fontWeight: FontWeight.bold),
              ),
            ),
            Padding(
              padding: EdgeInsets.all(8.0),
              child: Text(
                'Remote',
                style: TextStyle(fontWeight: FontWeight.bold),
              ),
            ),
          ],
        ),
        ...fields.map((field) => TableRow(
          children: [
            Padding(
              padding: const EdgeInsets.all(8.0),
              child: Text(field),
            ),
            Padding(
              padding: const EdgeInsets.all(8.0),
              child: Text(
                _formatValue(localData[field]),
                style: _getValueStyle(
                  localData[field],
                  remoteData[field],
                  true,
                ),
              ),
            ),
            Padding(
              padding: const EdgeInsets.all(8.0),
              child: Text(
                _formatValue(remoteData[field]),
                style: _getValueStyle(
                  localData[field],
                  remoteData[field],
                  false,
                ),
              ),
            ),
          ],
        )),
      ],
    );
  }
  
  List<String> _getComparableFields() {
    switch (entityType) {
      case SyncEntity.garment:
        return ['name', 'category', 'color', 'brand', 'size', 'wearCount', 'lastWornDate', 'updatedAt'];
      case SyncEntity.wardrobe:
        return ['name', 'description', 'isShared', 'updatedAt'];
      case SyncEntity.outfit:
        return ['name', 'occasion', 'season', 'rating', 'wearCount', 'updatedAt'];
      default:
        return ['name', 'updatedAt'];
    }
  }
  
  String _formatValue(dynamic value) {
    if (value == null) return 'Not set';
    if (value is DateTime) return value.toLocal().toString();
    if (value is List) return value.join(', ');
    return value.toString();
  }
  
  TextStyle? _getValueStyle(dynamic localValue, dynamic remoteValue, bool isLocal) {
    if (localValue?.toString() != remoteValue?.toString()) {
      return TextStyle(
        color: isLocal ? Colors.orange : Colors.blue,
        fontWeight: FontWeight.bold,
      );
    }
    return null;
  }
}