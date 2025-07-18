import 'package:drift/drift.dart';
import 'package:koutu/data/datasources/local/database/app_database.dart';
import 'package:koutu/data/models/garment/garment_model.dart';
import 'package:koutu/data/models/wardrobe/wardrobe_model.dart';
import 'package:flutter/foundation.dart';

/// Database query optimizer for efficient data retrieval
class QueryOptimizer {
  final AppDatabase _database;
  
  // Query cache for frequently accessed data
  final Map<String, CachedQuery> _queryCache = {};
  static const Duration _cacheExpiration = Duration(minutes: 5);
  
  QueryOptimizer(this._database);
  
  /// Get garments with optimized query using indexes and selective loading
  Future<List<GarmentModel>> getOptimizedGarments({
    required String wardrobeId,
    String? category,
    String? color,
    List<String>? tags,
    int? limit,
    int? offset,
    String sortBy = 'createdAt',
    bool ascending = false,
    bool includeImages = true,
  }) async {
    // Generate cache key
    final cacheKey = _generateCacheKey('garments', {
      'wardrobeId': wardrobeId,
      'category': category,
      'color': color,
      'tags': tags?.join(','),
      'limit': limit,
      'offset': offset,
      'sortBy': sortBy,
      'ascending': ascending,
    });
    
    // Check cache
    final cached = _getFromCache(cacheKey);
    if (cached != null) {
      return cached as List<GarmentModel>;
    }
    
    // Build optimized query
    final query = _database.select(_database.garments);
    
    // Use index on wardrobeId
    query.where((tbl) => tbl.wardrobeId.equals(wardrobeId));
    
    // Apply filters with index usage
    if (category != null) {
      query.where((tbl) => tbl.category.equals(category));
    }
    if (color != null) {
      query.where((tbl) => tbl.color.equals(color));
    }
    
    // Apply sorting with index optimization
    query.orderBy([
      (tbl) {
        switch (sortBy) {
          case 'name':
            return OrderingTerm(
              expression: tbl.name,
              mode: ascending ? OrderingMode.asc : OrderingMode.desc,
            );
          case 'category':
            return OrderingTerm(
              expression: tbl.category,
              mode: ascending ? OrderingMode.asc : OrderingMode.desc,
            );
          case 'createdAt':
          default:
            return OrderingTerm(
              expression: tbl.createdAt,
              mode: ascending ? OrderingMode.asc : OrderingMode.desc,
            );
        }
      }
    ]);
    
    // Apply limit and offset for pagination
    if (limit != null) {
      query.limit(limit, offset: offset);
    }
    
    // Execute query
    final garmentEntities = await query.get();
    
    // Batch load images if needed
    final garments = <GarmentModel>[];
    
    if (includeImages && garmentEntities.isNotEmpty) {
      // Batch load all images in one query
      final garmentIds = garmentEntities.map((g) => g.id).toList();
      final imagesMap = await _batchLoadImages(garmentIds);
      
      // Convert to models with images
      for (final entity in garmentEntities) {
        final images = imagesMap[entity.id] ?? [];
        garments.add(_convertToGarmentModel(entity, images));
      }
    } else {
      // Convert without images for better performance
      for (final entity in garmentEntities) {
        garments.add(_convertToGarmentModel(entity, []));
      }
    }
    
    // Filter by tags if specified (post-query filtering)
    final filteredGarments = tags != null && tags.isNotEmpty
        ? garments.where((g) => g.tags.any((tag) => tags.contains(tag))).toList()
        : garments;
    
    // Cache result
    _addToCache(cacheKey, filteredGarments);
    
    return filteredGarments;
  }
  
  /// Get wardrobe statistics with optimized aggregation query
  Future<WardrobeStatistics> getOptimizedWardrobeStatistics(
    String wardrobeId,
  ) async {
    final cacheKey = _generateCacheKey('wardrobe_stats', {'id': wardrobeId});
    
    final cached = _getFromCache(cacheKey);
    if (cached != null) {
      return cached as WardrobeStatistics;
    }
    
    // Use aggregation query for efficiency
    final countQuery = _database.selectOnly(_database.garments)
      ..addColumns([_database.garments.id.count()])
      ..where(_database.garments.wardrobeId.equals(wardrobeId));
    
    final totalItems = await countQuery
        .map((row) => row.read(_database.garments.id.count()) ?? 0)
        .getSingle();
    
    // Get category breakdown with single query
    final categoryQuery = _database.selectOnly(_database.garments)
      ..addColumns([
        _database.garments.category,
        _database.garments.id.count(),
      ])
      ..where(_database.garments.wardrobeId.equals(wardrobeId))
      ..groupBy([_database.garments.category]);
    
    final categoryBreakdown = <String, int>{};
    await categoryQuery.map((row) {
      final category = row.read(_database.garments.category);
      final count = row.read(_database.garments.id.count());
      if (category != null && count != null) {
        categoryBreakdown[category] = count;
      }
      return null;
    }).get();
    
    // Get total value with aggregation
    final valueQuery = _database.selectOnly(_database.garments)
      ..addColumns([
        _database.garments.currentValue.sum(),
      ])
      ..where(_database.garments.wardrobeId.equals(wardrobeId));
    
    final totalValue = await valueQuery
        .map((row) => row.read(_database.garments.currentValue.sum()) ?? 0.0)
        .getSingle();
    
    final statistics = WardrobeStatistics(
      totalItems: totalItems,
      categories: categoryBreakdown,
      totalValue: totalValue,
      lastUpdated: DateTime.now(),
    );
    
    _addToCache(cacheKey, statistics);
    
    return statistics;
  }
  
  /// Search garments with full-text search optimization
  Future<List<GarmentModel>> searchGarmentsOptimized({
    required String query,
    String? wardrobeId,
    int limit = 20,
  }) async {
    if (query.isEmpty) return [];
    
    // Use custom search query with multiple fields
    final searchQuery = _database.customSelect(
      '''
      SELECT DISTINCT g.* 
      FROM garments g
      WHERE (
        g.name LIKE ? OR 
        g.brand LIKE ? OR 
        g.category LIKE ? OR 
        g.color LIKE ? OR
        g.tags LIKE ?
      )
      ${wardrobeId != null ? 'AND g.wardrobe_id = ?' : ''}
      ORDER BY 
        CASE 
          WHEN g.name LIKE ? THEN 1
          WHEN g.brand LIKE ? THEN 2
          WHEN g.category LIKE ? THEN 3
          ELSE 4
        END,
        g.created_at DESC
      LIMIT ?
      ''',
      variables: [
        Variable.withString('%$query%'), // name
        Variable.withString('%$query%'), // brand
        Variable.withString('%$query%'), // category
        Variable.withString('%$query%'), // color
        Variable.withString('%$query%'), // tags
        if (wardrobeId != null) Variable.withString(wardrobeId),
        Variable.withString('$query%'), // name starts with (priority)
        Variable.withString('$query%'), // brand starts with
        Variable.withString('$query%'), // category starts with
        Variable.withInt(limit),
      ],
      readsFrom: {_database.garments},
    );
    
    final results = await searchQuery.get();
    
    // Convert to models
    final garments = <GarmentModel>[];
    for (final row in results) {
      final garmentData = row.data;
      final entity = Garment(
        id: garmentData['id'] as String,
        wardrobeId: garmentData['wardrobe_id'] as String,
        name: garmentData['name'] as String,
        category: garmentData['category'] as String,
        color: garmentData['color'] as String,
        brand: garmentData['brand'] as String,
        size: garmentData['size'] as String,
        material: garmentData['material'] as String?,
        careInstructions: garmentData['care_instructions'] as String?,
        tags: garmentData['tags'] as String?,
        purchaseDate: garmentData['purchase_date'] != null 
            ? DateTime.parse(garmentData['purchase_date'] as String)
            : null,
        purchasePrice: garmentData['purchase_price'] as double?,
        currentValue: garmentData['current_value'] as double?,
        wearCount: garmentData['wear_count'] as int?,
        lastWornDate: garmentData['last_worn_date'] != null
            ? DateTime.parse(garmentData['last_worn_date'] as String)
            : null,
        season: garmentData['season'] as String?,
        notes: garmentData['notes'] as String?,
        createdAt: DateTime.parse(garmentData['created_at'] as String),
        updatedAt: DateTime.parse(garmentData['updated_at'] as String),
      );
      
      garments.add(_convertToGarmentModel(entity, []));
    }
    
    return garments;
  }
  
  /// Batch update garments with single transaction
  Future<void> batchUpdateGarments(
    List<String> garmentIds,
    Map<String, dynamic> updates,
  ) async {
    await _database.transaction(() async {
      // Build update query
      final updateQuery = _database.update(_database.garments)
        ..where((tbl) => tbl.id.isIn(garmentIds));
      
      // Apply updates
      final companion = GarmentsCompanion(
        updatedAt: Value(DateTime.now()),
      );
      
      if (updates['category'] != null) {
        companion.copyWith(category: Value(updates['category']));
      }
      if (updates['tags'] != null) {
        companion.copyWith(tags: Value(updates['tags']));
      }
      // Add more fields as needed
      
      await updateQuery.write(companion);
      
      // Clear cache for affected items
      _clearCacheForGarments(garmentIds);
    });
  }
  
  /// Create database indexes for better performance
  Future<void> createOptimizationIndexes() async {
    await _database.customStatement('''
      CREATE INDEX IF NOT EXISTS idx_garments_wardrobe_category 
      ON garments(wardrobe_id, category);
    ''');
    
    await _database.customStatement('''
      CREATE INDEX IF NOT EXISTS idx_garments_wardrobe_created 
      ON garments(wardrobe_id, created_at DESC);
    ''');
    
    await _database.customStatement('''
      CREATE INDEX IF NOT EXISTS idx_garments_search 
      ON garments(name, brand, category);
    ''');
    
    await _database.customStatement('''
      CREATE INDEX IF NOT EXISTS idx_images_garment 
      ON images(garment_id);
    ''');
    
    await _database.customStatement('''
      CREATE INDEX IF NOT EXISTS idx_outfits_wardrobe_created 
      ON outfits(wardrobe_id, created_at DESC);
    ''');
  }
  
  /// Vacuum database for optimal performance
  Future<void> optimizeDatabase() async {
    await _database.customStatement('VACUUM;');
    await _database.customStatement('ANALYZE;');
  }
  
  /// Get database statistics
  Future<DatabaseStatistics> getDatabaseStatistics() async {
    final tables = ['garments', 'wardrobes', 'images', 'outfits'];
    final stats = <String, int>{};
    
    for (final table in tables) {
      final countQuery = await _database.customSelect(
        'SELECT COUNT(*) as count FROM $table',
        readsFrom: {},
      ).getSingle();
      
      stats[table] = countQuery.data['count'] as int;
    }
    
    // Get database size
    final sizeQuery = await _database.customSelect(
      'SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size()',
      readsFrom: {},
    ).getSingle();
    
    final dbSize = sizeQuery.data['size'] as int;
    
    return DatabaseStatistics(
      tableCounts: stats,
      totalSize: dbSize,
      lastOptimized: DateTime.now(),
    );
  }
  
  // Helper methods
  
  Future<Map<String, List<Image>>> _batchLoadImages(
    List<String> garmentIds,
  ) async {
    final imagesMap = <String, List<Image>>{};
    
    if (garmentIds.isEmpty) return imagesMap;
    
    // Load all images in one query
    final imagesQuery = _database.select(_database.images)
      ..where((tbl) => tbl.garmentId.isIn(garmentIds))
      ..orderBy([(tbl) => OrderingTerm(expression: tbl.createdAt)]);
    
    final images = await imagesQuery.get();
    
    // Group by garment ID
    for (final image in images) {
      imagesMap[image.garmentId] ??= [];
      imagesMap[image.garmentId]!.add(image);
    }
    
    return imagesMap;
  }
  
  GarmentModel _convertToGarmentModel(
    Garment entity,
    List<Image> images,
  ) {
    return GarmentModel(
      id: entity.id,
      wardrobeId: entity.wardrobeId,
      name: entity.name,
      category: entity.category,
      color: entity.color,
      brand: entity.brand,
      size: entity.size,
      material: entity.material ?? '',
      careInstructions: entity.careInstructions?.split(',') ?? [],
      tags: entity.tags?.split(',') ?? [],
      purchaseDate: entity.purchaseDate,
      purchasePrice: entity.purchasePrice,
      currentValue: entity.currentValue,
      wearCount: entity.wearCount ?? 0,
      lastWornDate: entity.lastWornDate,
      season: entity.season,
      notes: entity.notes,
      images: images.map((img) => ImageModel(
        id: img.id,
        url: img.url,
        thumbnailUrl: img.thumbnailUrl,
        width: img.width ?? 0,
        height: img.height ?? 0,
        size: img.size ?? 0,
        createdAt: img.createdAt,
      )).toList(),
      createdAt: entity.createdAt,
      updatedAt: entity.updatedAt,
    );
  }
  
  String _generateCacheKey(String prefix, Map<String, dynamic> params) {
    final sortedParams = params.entries.toList()
      ..sort((a, b) => a.key.compareTo(b.key));
    
    final paramString = sortedParams
        .where((e) => e.value != null)
        .map((e) => '${e.key}:${e.value}')
        .join('|');
    
    return '$prefix|$paramString';
  }
  
  dynamic _getFromCache(String key) {
    final cached = _queryCache[key];
    if (cached != null && !cached.isExpired) {
      return cached.data;
    }
    _queryCache.remove(key);
    return null;
  }
  
  void _addToCache(String key, dynamic data) {
    _queryCache[key] = CachedQuery(
      data: data,
      timestamp: DateTime.now(),
      expiration: _cacheExpiration,
    );
    
    // Clean old cache entries periodically
    if (_queryCache.length > 100) {
      _cleanCache();
    }
  }
  
  void _cleanCache() {
    _queryCache.removeWhere((key, value) => value.isExpired);
  }
  
  void _clearCacheForGarments(List<String> garmentIds) {
    // Clear any cache entries that might contain these garments
    _queryCache.removeWhere((key, value) {
      return key.contains('garments') || 
             garmentIds.any((id) => key.contains(id));
    });
  }
}

/// Cached query model
class CachedQuery {
  final dynamic data;
  final DateTime timestamp;
  final Duration expiration;
  
  CachedQuery({
    required this.data,
    required this.timestamp,
    required this.expiration,
  });
  
  bool get isExpired => 
      DateTime.now().difference(timestamp) > expiration;
}

/// Database statistics model
class DatabaseStatistics {
  final Map<String, int> tableCounts;
  final int totalSize;
  final DateTime lastOptimized;
  
  DatabaseStatistics({
    required this.tableCounts,
    required this.totalSize,
    required this.lastOptimized,
  });
  
  String get formattedSize {
    if (totalSize < 1024) return '${totalSize}B';
    if (totalSize < 1024 * 1024) {
      return '${(totalSize / 1024).toStringAsFixed(1)}KB';
    }
    return '${(totalSize / 1024 / 1024).toStringAsFixed(1)}MB';
  }
}