import 'package:drift/drift.dart';
import 'package:koutu/data/local/database/converters/string_list_converter.dart';
import 'package:koutu/data/local/database/converters/map_converter.dart';

class Wardrobes extends Table {
  TextColumn get id => text()();
  TextColumn get userId => text()();
  TextColumn get name => text()();
  TextColumn get description => text().nullable()();
  TextColumn get imageUrl => text().nullable()();
  TextColumn get garmentIds => text().map(const StringListConverter()).withDefault(const Constant('[]'))();
  BoolColumn get isShared => boolean().withDefault(const Constant(false))();
  TextColumn get sharedWithUserIds => text().map(const StringListConverter()).withDefault(const Constant('[]'))();
  BoolColumn get isDefault => boolean().withDefault(const Constant(false))();
  IntColumn get sortOrder => integer().withDefault(const Constant(0))();
  TextColumn get colorTheme => text().nullable()();
  TextColumn get iconName => text().nullable()();
  TextColumn get metadata => text().map(const MapConverter()).nullable()();
  DateTimeColumn get createdAt => dateTime()();
  DateTimeColumn get updatedAt => dateTime()();
  DateTimeColumn get lastSyncedAt => dateTime().nullable()();

  @override
  Set<Column> get primaryKey => {id};
}