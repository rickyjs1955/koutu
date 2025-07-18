import 'package:drift/drift.dart';
import 'package:koutu/data/local/database/app_database.dart';
import 'package:koutu/data/local/database/tables/garments_table.dart';
import 'package:koutu/data/models/garment/garment_model.dart';

part 'garment_dao.g.dart';

@DriftAccessor(tables: [Garments])
class GarmentDao extends DatabaseAccessor<AppDatabase> with _$GarmentDaoMixin {
  GarmentDao(AppDatabase db) : super(db);

  /// Get all garments for a wardrobe
  Future<List<Garment>> getGarmentsForWardrobe(String wardrobeId) async {
    return await (select(garments)
          ..where((g) => g.wardrobeId.equals(wardrobeId))
          ..orderBy([(g) => OrderingTerm(expression: g.updatedAt, mode: OrderingMode.desc)]))
        .get();
  }

  /// Get garment by ID
  Future<Garment?> getGarmentById(String id) async {
    return await (select(garments)..where((g) => g.id.equals(id))).getSingleOrNull();
  }

  /// Get garments by category
  Future<List<Garment>> getGarmentsByCategory(String wardrobeId, String category) async {
    return await (select(garments)
          ..where((g) => g.wardrobeId.equals(wardrobeId) & g.category.equals(category)))
        .get();
  }

  /// Get favorite garments
  Future<List<Garment>> getFavoriteGarments(String wardrobeId) async {
    return await (select(garments)
          ..where((g) => g.wardrobeId.equals(wardrobeId) & g.isFavorite.equals(true)))
        .get();
  }

  /// Search garments
  Future<List<Garment>> searchGarments(String wardrobeId, String query) async {
    final searchTerm = '%${query.toLowerCase()}%';
    return await (select(garments)
          ..where((g) =>
              g.wardrobeId.equals(wardrobeId) &
              (g.name.lower().like(searchTerm) |
                  g.description.lower().like(searchTerm) |
                  g.brand.lower().like(searchTerm) |
                  g.tags.like(searchTerm))))
        .get();
  }

  /// Get garments by multiple IDs
  Future<List<Garment>> getGarmentsByIds(List<String> ids) async {
    return await (select(garments)..where((g) => g.id.isIn(ids))).get();
  }

  /// Insert or update garment
  Future<void> upsertGarment(GarmentModel garmentModel) async {
    await into(garments).insertOnConflictUpdate(
      Garment(
        id: garmentModel.id,
        wardrobeId: garmentModel.wardrobeId,
        userId: garmentModel.userId,
        name: garmentModel.name,
        description: garmentModel.description,
        category: garmentModel.category,
        subcategory: garmentModel.subcategory,
        brand: garmentModel.brand,
        size: garmentModel.size,
        colors: garmentModel.colors,
        tags: garmentModel.tags,
        imageIds: garmentModel.imageIds,
        primaryImageId: garmentModel.primaryImageId,
        purchasePrice: garmentModel.purchasePrice,
        purchaseDate: garmentModel.purchaseDate,
        purchaseLocation: garmentModel.purchaseLocation,
        wearCount: garmentModel.wearCount,
        lastWornDate: garmentModel.lastWornDate,
        isFavorite: garmentModel.isFavorite,
        season: garmentModel.season,
        occasion: garmentModel.occasion,
        material: garmentModel.material,
        careInstructions: garmentModel.careInstructions,
        notes: garmentModel.notes,
        metadata: garmentModel.metadata,
        createdAt: garmentModel.createdAt,
        updatedAt: garmentModel.updatedAt,
        lastSyncedAt: DateTime.now(),
      ),
    );
  }

  /// Update wear count and last worn date
  Future<void> recordWear(String garmentId) async {
    final garment = await getGarmentById(garmentId);
    if (garment != null) {
      await (update(garments)..where((g) => g.id.equals(garmentId))).write(
        GarmentsCompanion(
          wearCount: Value(garment.wearCount + 1),
          lastWornDate: Value(DateTime.now()),
          updatedAt: Value(DateTime.now()),
        ),
      );
    }
  }

  /// Toggle favorite status
  Future<void> toggleFavorite(String garmentId) async {
    final garment = await getGarmentById(garmentId);
    if (garment != null) {
      await (update(garments)..where((g) => g.id.equals(garmentId))).write(
        GarmentsCompanion(
          isFavorite: Value(!garment.isFavorite),
          updatedAt: Value(DateTime.now()),
        ),
      );
    }
  }

  /// Bulk update garments
  Future<void> bulkUpdateGarments(
    List<String> garmentIds,
    GarmentsCompanion updates,
  ) async {
    await (update(garments)..where((g) => g.id.isIn(garmentIds))).write(updates);
  }

  /// Delete garment
  Future<void> deleteGarment(String garmentId) async {
    await (delete(garments)..where((g) => g.id.equals(garmentId))).go();
  }

  /// Delete multiple garments
  Future<void> deleteGarments(List<String> garmentIds) async {
    await (delete(garments)..where((g) => g.id.isIn(garmentIds))).go();
  }

  /// Get garment statistics
  Future<Map<String, dynamic>> getGarmentStatistics(String wardrobeId) async {
    final allGarments = await getGarmentsForWardrobe(wardrobeId);
    
    final stats = <String, dynamic>{
      'totalCount': allGarments.length,
      'favoriteCount': allGarments.where((g) => g.isFavorite).length,
      'totalWearCount': allGarments.fold<int>(0, (sum, g) => sum + g.wearCount),
      'categoryCounts': <String, int>{},
      'brandCounts': <String, int>{},
      'colorCounts': <String, int>{},
    };

    for (final garment in allGarments) {
      // Category counts
      stats['categoryCounts'][garment.category] = 
          (stats['categoryCounts'][garment.category] ?? 0) + 1;
      
      // Brand counts
      if (garment.brand != null) {
        stats['brandCounts'][garment.brand!] = 
            (stats['brandCounts'][garment.brand!] ?? 0) + 1;
      }
      
      // Color counts
      for (final color in garment.colors) {
        stats['colorCounts'][color] = (stats['colorCounts'][color] ?? 0) + 1;
      }
    }

    return stats;
  }

  /// Convert database garment to GarmentModel
  GarmentModel garmentToModel(Garment garment) {
    return GarmentModel(
      id: garment.id,
      wardrobeId: garment.wardrobeId,
      userId: garment.userId,
      name: garment.name,
      description: garment.description,
      category: garment.category,
      subcategory: garment.subcategory,
      brand: garment.brand,
      size: garment.size,
      colors: garment.colors,
      tags: garment.tags,
      imageIds: garment.imageIds,
      primaryImageId: garment.primaryImageId,
      purchasePrice: garment.purchasePrice,
      purchaseDate: garment.purchaseDate,
      purchaseLocation: garment.purchaseLocation,
      wearCount: garment.wearCount,
      lastWornDate: garment.lastWornDate,
      isFavorite: garment.isFavorite,
      season: garment.season,
      occasion: garment.occasion,
      material: garment.material,
      careInstructions: garment.careInstructions,
      notes: garment.notes,
      metadata: garment.metadata,
      createdAt: garment.createdAt,
      updatedAt: garment.updatedAt,
    );
  }
}