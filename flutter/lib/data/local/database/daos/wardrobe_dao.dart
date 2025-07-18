import 'package:drift/drift.dart';
import 'package:koutu/data/local/database/app_database.dart';
import 'package:koutu/data/local/database/tables/wardrobes_table.dart';
import 'package:koutu/data/models/wardrobe/wardrobe_model.dart';

part 'wardrobe_dao.g.dart';

@DriftAccessor(tables: [Wardrobes])
class WardrobeDao extends DatabaseAccessor<AppDatabase> with _$WardrobeDaoMixin {
  WardrobeDao(AppDatabase db) : super(db);

  /// Get all wardrobes for a user
  Future<List<Wardrobe>> getWardrobesForUser(String userId) async {
    return await (select(wardrobes)
          ..where((w) => w.userId.equals(userId))
          ..orderBy([(w) => OrderingTerm(expression: w.sortOrder)]))
        .get();
  }

  /// Get wardrobe by ID
  Future<Wardrobe?> getWardrobeById(String id) async {
    return await (select(wardrobes)..where((w) => w.id.equals(id))).getSingleOrNull();
  }

  /// Get shared wardrobes for a user
  Future<List<Wardrobe>> getSharedWardrobesForUser(String userId) async {
    return await (select(wardrobes)
          ..where((w) => w.sharedWithUserIds.contains(userId) & w.isShared.equals(true)))
        .get();
  }

  /// Get default wardrobe for user
  Future<Wardrobe?> getDefaultWardrobe(String userId) async {
    return await (select(wardrobes)
          ..where((w) => w.userId.equals(userId) & w.isDefault.equals(true)))
        .getSingleOrNull();
  }

  /// Insert or update wardrobe
  Future<void> upsertWardrobe(WardrobeModel wardrobeModel) async {
    await into(wardrobes).insertOnConflictUpdate(
      Wardrobe(
        id: wardrobeModel.id,
        userId: wardrobeModel.userId,
        name: wardrobeModel.name,
        description: wardrobeModel.description,
        imageUrl: wardrobeModel.imageUrl,
        garmentIds: wardrobeModel.garmentIds,
        isShared: wardrobeModel.isShared,
        sharedWithUserIds: wardrobeModel.sharedWithUserIds,
        isDefault: wardrobeModel.isDefault,
        sortOrder: wardrobeModel.sortOrder,
        colorTheme: wardrobeModel.colorTheme,
        iconName: wardrobeModel.iconName,
        metadata: wardrobeModel.metadata,
        createdAt: wardrobeModel.createdAt,
        updatedAt: wardrobeModel.updatedAt,
        lastSyncedAt: DateTime.now(),
      ),
    );
  }

  /// Add garment to wardrobe
  Future<void> addGarmentToWardrobe(String wardrobeId, String garmentId) async {
    final wardrobe = await getWardrobeById(wardrobeId);
    if (wardrobe != null) {
      final garmentIds = List<String>.from(wardrobe.garmentIds);
      if (!garmentIds.contains(garmentId)) {
        garmentIds.add(garmentId);
        await (update(wardrobes)..where((w) => w.id.equals(wardrobeId))).write(
          WardrobesCompanion(
            garmentIds: Value(garmentIds),
            updatedAt: Value(DateTime.now()),
          ),
        );
      }
    }
  }

  /// Remove garment from wardrobe
  Future<void> removeGarmentFromWardrobe(String wardrobeId, String garmentId) async {
    final wardrobe = await getWardrobeById(wardrobeId);
    if (wardrobe != null) {
      final garmentIds = List<String>.from(wardrobe.garmentIds);
      garmentIds.remove(garmentId);
      await (update(wardrobes)..where((w) => w.id.equals(wardrobeId))).write(
        WardrobesCompanion(
          garmentIds: Value(garmentIds),
          updatedAt: Value(DateTime.now()),
        ),
      );
    }
  }

  /// Update wardrobe sharing
  Future<void> updateWardrobeSharing(
    String wardrobeId,
    bool isShared,
    List<String> sharedWithUserIds,
  ) async {
    await (update(wardrobes)..where((w) => w.id.equals(wardrobeId))).write(
      WardrobesCompanion(
        isShared: Value(isShared),
        sharedWithUserIds: Value(sharedWithUserIds),
        updatedAt: Value(DateTime.now()),
      ),
    );
  }

  /// Set default wardrobe
  Future<void> setDefaultWardrobe(String userId, String wardrobeId) async {
    await transaction(() async {
      // Remove default from all other wardrobes
      await (update(wardrobes)..where((w) => w.userId.equals(userId))).write(
        const WardrobesCompanion(isDefault: Value(false)),
      );
      
      // Set the new default
      await (update(wardrobes)..where((w) => w.id.equals(wardrobeId))).write(
        const WardrobesCompanion(isDefault: Value(true)),
      );
    });
  }

  /// Delete wardrobe
  Future<void> deleteWardrobe(String wardrobeId) async {
    await (delete(wardrobes)..where((w) => w.id.equals(wardrobeId))).go();
  }

  /// Get wardrobe count for user
  Future<int> getWardrobeCount(String userId) async {
    final count = await (selectOnly(wardrobes)
          ..where(wardrobes.userId.equals(userId))
          ..addColumns([wardrobes.id.count()]))
        .getSingle();
    return count.read(wardrobes.id.count()) ?? 0;
  }

  /// Convert database wardrobe to WardrobeModel
  WardrobeModel wardrobeToModel(Wardrobe wardrobe) {
    return WardrobeModel(
      id: wardrobe.id,
      userId: wardrobe.userId,
      name: wardrobe.name,
      description: wardrobe.description,
      imageUrl: wardrobe.imageUrl,
      garmentIds: wardrobe.garmentIds,
      isShared: wardrobe.isShared,
      sharedWithUserIds: wardrobe.sharedWithUserIds,
      isDefault: wardrobe.isDefault,
      sortOrder: wardrobe.sortOrder,
      colorTheme: wardrobe.colorTheme,
      iconName: wardrobe.iconName,
      metadata: wardrobe.metadata,
      createdAt: wardrobe.createdAt,
      updatedAt: wardrobe.updatedAt,
    );
  }
}