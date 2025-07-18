import 'dart:io';

import 'package:drift/drift.dart';
import 'package:drift/native.dart';
import 'package:path_provider/path_provider.dart';
import 'package:path/path.dart' as p;
import 'package:koutu/data/local/database/tables/users_table.dart';
import 'package:koutu/data/local/database/tables/wardrobes_table.dart';
import 'package:koutu/data/local/database/tables/garments_table.dart';
import 'package:koutu/data/local/database/tables/images_table.dart';
import 'package:koutu/data/local/database/tables/sync_queue_table.dart';
import 'package:koutu/data/local/database/daos/user_dao.dart';
import 'package:koutu/data/local/database/daos/wardrobe_dao.dart';
import 'package:koutu/data/local/database/daos/garment_dao.dart';
import 'package:koutu/data/local/database/daos/image_dao.dart';
import 'package:koutu/data/local/database/daos/sync_queue_dao.dart';
import 'package:koutu/data/local/database/converters/datetime_converter.dart';
import 'package:koutu/data/local/database/converters/string_list_converter.dart';
import 'package:koutu/data/local/database/converters/map_converter.dart';

part 'app_database.g.dart';

@DriftDatabase(
  tables: [
    Users,
    Wardrobes,
    Garments,
    Images,
    SyncQueue,
  ],
  daos: [
    UserDao,
    WardrobeDao,
    GarmentDao,
    ImageDao,
    SyncQueueDao,
  ],
)
class AppDatabase extends _$AppDatabase {
  AppDatabase() : super(_openConnection());

  @override
  int get schemaVersion => 1;

  @override
  MigrationStrategy get migration {
    return MigrationStrategy(
      onCreate: (Migrator m) async {
        await m.createAll();
      },
      onUpgrade: (Migrator m, int from, int to) async {
        // Add migration logic here when schema changes
      },
      beforeOpen: (details) async {
        await customStatement('PRAGMA foreign_keys = ON');
      },
    );
  }

  /// Clear all data from the database
  Future<void> clearAllData() async {
    await transaction(() async {
      for (final table in allTables) {
        await delete(table).go();
      }
    });
  }

  /// Get database size in bytes
  Future<int> getDatabaseSize() async {
    final dbFolder = await getApplicationDocumentsDirectory();
    final file = File(p.join(dbFolder.path, 'koutu.db'));
    if (await file.exists()) {
      return await file.length();
    }
    return 0;
  }

  /// Delete old cached data based on age
  Future<void> deleteOldCachedData(Duration maxAge) async {
    final cutoffDate = DateTime.now().subtract(maxAge);
    
    await transaction(() async {
      // Delete old images
      await (delete(images)..where((i) => i.createdAt.isSmallerThan(cutoffDate))).go();
      
      // Delete orphaned garments
      await customStatement('''
        DELETE FROM garments 
        WHERE id NOT IN (
          SELECT DISTINCT garment_id FROM sync_queue WHERE garment_id IS NOT NULL
        ) AND updated_at < ?
      ''', [cutoffDate.millisecondsSinceEpoch]);
    });
  }

  /// Optimize database
  Future<void> optimizeDatabase() async {
    await customStatement('VACUUM');
    await customStatement('ANALYZE');
  }
}

LazyDatabase _openConnection() {
  return LazyDatabase(() async {
    final dbFolder = await getApplicationDocumentsDirectory();
    final file = File(p.join(dbFolder.path, 'koutu.db'));
    return NativeDatabase.createInBackground(file);
  });
}