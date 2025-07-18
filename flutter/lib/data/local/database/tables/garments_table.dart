import 'package:drift/drift.dart';
import 'package:koutu/data/local/database/converters/string_list_converter.dart';
import 'package:koutu/data/local/database/converters/map_converter.dart';

class Garments extends Table {
  TextColumn get id => text()();
  TextColumn get wardrobeId => text()();
  TextColumn get userId => text()();
  TextColumn get name => text()();
  TextColumn get description => text().nullable()();
  TextColumn get category => text()();
  TextColumn get subcategory => text().nullable()();
  TextColumn get brand => text().nullable()();
  TextColumn get size => text().nullable()();
  TextColumn get colors => text().map(const StringListConverter()).withDefault(const Constant('[]'))();
  TextColumn get tags => text().map(const StringListConverter()).withDefault(const Constant('[]'))();
  TextColumn get imageIds => text().map(const StringListConverter()).withDefault(const Constant('[]'))();
  TextColumn get primaryImageId => text().nullable()();
  RealColumn get purchasePrice => real().nullable()();
  DateTimeColumn get purchaseDate => dateTime().nullable()();
  TextColumn get purchaseLocation => text().nullable()();
  IntColumn get wearCount => integer().withDefault(const Constant(0))();
  DateTimeColumn get lastWornDate => dateTime().nullable()();
  BoolColumn get isFavorite => boolean().withDefault(const Constant(false))();
  TextColumn get season => text().map(const StringListConverter()).withDefault(const Constant('[]'))();
  TextColumn get occasion => text().map(const StringListConverter()).withDefault(const Constant('[]'))();
  TextColumn get material => text().map(const StringListConverter()).withDefault(const Constant('[]'))();
  TextColumn get careInstructions => text().nullable()();
  TextColumn get notes => text().nullable()();
  TextColumn get metadata => text().map(const MapConverter()).nullable()();
  DateTimeColumn get createdAt => dateTime()();
  DateTimeColumn get updatedAt => dateTime()();
  DateTimeColumn get lastSyncedAt => dateTime().nullable()();

  @override
  Set<Column> get primaryKey => {id};
}