import 'package:flutter/foundation.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:koutu/data/models/garment/garment_model.dart';
import 'package:koutu/data/models/wardrobe/wardrobe_model.dart';
import 'package:koutu/data/models/user/user_model.dart';
import 'package:koutu/services/performance/lazy_loading_service.dart';
import 'package:dartz/dartz.dart';
import 'package:drift/drift.dart';
import 'package:koutu/data/datasources/local/database/app_database.dart';

/// Repository for efficient lazy loading of large datasets
class LazyDataRepository {
  final AppDatabase _database;
  
  LazyDataRepository(this._database);
  
  /// Get paginated garments with efficient query
  Future<Either<Failure, PaginatedResult<GarmentModel>>> getPaginatedGarments({
    required String wardrobeId,
    required int page,
    required int pageSize,
    String? category,
    String? color,
    String? brand,
    List<String>? tags,
    String sortBy = 'createdAt',
    bool ascending = false,
  }) async {
    try {
      // Build efficient query with filters
      final query = _database.select(_database.garments)
        ..where((tbl) => tbl.wardrobeId.equals(wardrobeId));
      
      // Apply filters
      if (category != null) {
        query.where((tbl) => tbl.category.equals(category));
      }
      if (color != null) {
        query.where((tbl) => tbl.color.equals(color));
      }
      if (brand != null) {
        query.where((tbl) => tbl.brand.equals(brand));
      }
      
      // Apply sorting
      query.orderBy([
        (tbl) {
          switch (sortBy) {
            case 'name':
              return OrderingTerm(expression: tbl.name, mode: ascending ? OrderingMode.asc : OrderingMode.desc);
            case 'category':
              return OrderingTerm(expression: tbl.category, mode: ascending ? OrderingMode.asc : OrderingMode.desc);
            case 'color':
              return OrderingTerm(expression: tbl.color, mode: ascending ? OrderingMode.asc : OrderingMode.desc);
            case 'createdAt':
            default:
              return OrderingTerm(expression: tbl.createdAt, mode: ascending ? OrderingMode.asc : OrderingMode.desc);
          }
        }
      ]);
      
      // Apply pagination
      query.limit(pageSize, offset: page * pageSize);
      
      // Execute query
      final results = await query.get();
      
      // Convert to models with lazy image loading
      final garments = await Future.wait(
        results.map((entity) => _convertToGarmentModel(entity)),
      );
      
      // Filter by tags if specified (post-query filtering)
      final filteredGarments = tags != null && tags.isNotEmpty
          ? garments.where((g) => g.tags.any((tag) => tags.contains(tag))).toList()
          : garments;
      
      // Check if there are more results
      final countQuery = _database.selectOnly(_database.garments)
        ..addColumns([_database.garments.id.count()]);
      
      if (category != null) {
        countQuery.where(_database.garments.category.equals(category));
      }
      if (wardrobeId.isNotEmpty) {
        countQuery.where(_database.garments.wardrobeId.equals(wardrobeId));
      }
      
      final totalCount = await countQuery.map((row) => row.read(_database.garments.id.count())).getSingle();
      
      return Right(PaginatedResult(
        items: filteredGarments,
        page: page,
        pageSize: pageSize,
        hasMore: (page + 1) * pageSize < (totalCount ?? 0),
        totalCount: totalCount,
      ));
    } catch (e) {
      return Left(DatabaseFailure(e.toString()));
    }
  }
  
  /// Get paginated wardrobes with efficient query
  Future<Either<Failure, PaginatedResult<WardrobeModel>>> getPaginatedWardrobes({
    required String userId,
    required int page,
    required int pageSize,
    String sortBy = 'createdAt',
    bool ascending = false,
  }) async {
    try {
      final query = _database.select(_database.wardrobes)
        ..where((tbl) => tbl.userId.equals(userId))
        ..orderBy([
          (tbl) {
            switch (sortBy) {
              case 'name':
                return OrderingTerm(expression: tbl.name, mode: ascending ? OrderingMode.asc : OrderingMode.desc);
              case 'itemCount':
                // Sort by garment count (requires join)
                return OrderingTerm(expression: tbl.createdAt, mode: ascending ? OrderingMode.asc : OrderingMode.desc);
              case 'createdAt':
              default:
                return OrderingTerm(expression: tbl.createdAt, mode: ascending ? OrderingMode.asc : OrderingMode.desc);
            }
          }
        ])
        ..limit(pageSize, offset: page * pageSize);
      
      final results = await query.get();
      
      // Convert to models with lazy statistics loading
      final wardrobes = await Future.wait(
        results.map((entity) => _convertToWardrobeModel(entity)),
      );
      
      // Get total count
      final totalCount = await (_database.selectOnly(_database.wardrobes)
        ..addColumns([_database.wardrobes.id.count()])
        ..where(_database.wardrobes.userId.equals(userId)))
        .map((row) => row.read(_database.wardrobes.id.count()))
        .getSingle();
      
      return Right(PaginatedResult(
        items: wardrobes,
        page: page,
        pageSize: pageSize,
        hasMore: (page + 1) * pageSize < (totalCount ?? 0),
        totalCount: totalCount,
      ));
    } catch (e) {
      return Left(DatabaseFailure(e.toString()));
    }
  }
  
  /// Stream paginated data with automatic updates
  Stream<PaginatedResult<GarmentModel>> streamPaginatedGarments({
    required String wardrobeId,
    required int pageSize,
    String? category,
    String sortBy = 'createdAt',
    bool ascending = false,
  }) async* {
    int currentPage = 0;
    bool hasMore = true;
    
    while (hasMore) {
      final result = await getPaginatedGarments(
        wardrobeId: wardrobeId,
        page: currentPage,
        pageSize: pageSize,
        category: category,
        sortBy: sortBy,
        ascending: ascending,
      );
      
      yield* result.fold(
        (failure) => throw failure,
        (paginatedResult) async* {
          yield paginatedResult;
          hasMore = paginatedResult.hasMore;
          currentPage++;
          
          // Add delay to prevent overwhelming the UI
          await Future.delayed(const Duration(milliseconds: 100));
        },
      );
    }
  }
  
  /// Batch load multiple items efficiently
  Future<Either<Failure, List<GarmentModel>>> batchLoadGarments(
    List<String> garmentIds,
  ) async {
    try {
      // Load in chunks to prevent memory issues
      const chunkSize = 50;
      final chunks = <List<String>>[];
      
      for (var i = 0; i < garmentIds.length; i += chunkSize) {
        final end = (i + chunkSize < garmentIds.length) ? i + chunkSize : garmentIds.length;
        chunks.add(garmentIds.sublist(i, end));
      }
      
      final allGarments = <GarmentModel>[];
      
      for (final chunk in chunks) {
        final query = _database.select(_database.garments)
          ..where((tbl) => tbl.id.isIn(chunk));
        
        final results = await query.get();
        final garments = await Future.wait(
          results.map((entity) => _convertToGarmentModel(entity)),
        );
        
        allGarments.addAll(garments);
      }
      
      return Right(allGarments);
    } catch (e) {
      return Left(DatabaseFailure(e.toString()));
    }
  }
  
  /// Preload data for better performance
  Future<void> preloadGarmentsForWardrobe(
    String wardrobeId, {
    int preloadPages = 3,
    int pageSize = 20,
  }) async {
    await LazyLoadingService.preloadPages<GarmentModel>(
      cacheKey: 'garments_$wardrobeId',
      pages: List.generate(preloadPages, (i) => i),
      pageSize: pageSize,
      loader: (page, size) async {
        final result = await getPaginatedGarments(
          wardrobeId: wardrobeId,
          page: page,
          pageSize: size,
        );
        
        return result.fold(
          (failure) => throw failure,
          (paginatedResult) => paginatedResult.items,
        );
      },
    );
  }
  
  // Helper methods
  
  Future<GarmentModel> _convertToGarmentModel(Garment entity) async {
    // Lazy load images separately
    final images = await (_database.select(_database.images)
      ..where((tbl) => tbl.garmentId.equals(entity.id)))
      .get();
    
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
  
  Future<WardrobeModel> _convertToWardrobeModel(Wardrobe entity) async {
    // Lazy load statistics
    final garmentCount = await (_database.selectOnly(_database.garments)
      ..addColumns([_database.garments.id.count()])
      ..where(_database.garments.wardrobeId.equals(entity.id)))
      .map((row) => row.read(_database.garments.id.count()))
      .getSingle();
    
    // Get categories count
    final categoriesQuery = _database.selectOnly(_database.garments, distinct: true)
      ..addColumns([_database.garments.category])
      ..where(_database.garments.wardrobeId.equals(entity.id));
    
    final categories = await categoriesQuery
      .map((row) => row.read(_database.garments.category))
      .get();
    
    return WardrobeModel(
      id: entity.id,
      userId: entity.userId,
      name: entity.name,
      description: entity.description ?? '',
      icon: entity.icon ?? '👔',
      coverImage: entity.coverImage,
      isShared: entity.isShared,
      sharedWith: entity.sharedWith?.split(',') ?? [],
      statistics: WardrobeStatistics(
        totalItems: garmentCount ?? 0,
        categories: Map.fromEntries(
          categories.where((c) => c != null).map((c) => MapEntry(c!, 0)),
        ),
        totalValue: 0,
        lastUpdated: entity.updatedAt,
      ),
      settings: WardrobeSettings(
        defaultView: entity.defaultView ?? 'grid',
        sortBy: entity.sortBy ?? 'name',
        groupBy: entity.groupBy,
        showStatistics: entity.showStatistics ?? true,
      ),
      createdAt: entity.createdAt,
      updatedAt: entity.updatedAt,
    );
  }
}