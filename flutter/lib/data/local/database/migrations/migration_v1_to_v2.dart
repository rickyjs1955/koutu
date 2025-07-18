import 'package:drift/drift.dart';

/// Example migration from v1 to v2
/// This is a template for future migrations
class MigrationV1ToV2 {
  static Future<void> migrate(Migrator m) async {
    // Example: Add new column to existing table
    // await m.addColumn(users, users.phoneNumber);
    
    // Example: Create new table
    // await m.createTable(newTable);
    
    // Example: Migrate data
    // await m.customStatement('''
    //   UPDATE users SET phone_number = '' WHERE phone_number IS NULL
    // ''');
    
    // Example: Create index
    // await m.createIndex(
    //   Index('idx_garments_wardrobe', 'CREATE INDEX idx_garments_wardrobe ON garments(wardrobe_id)'),
    // );
  }
}