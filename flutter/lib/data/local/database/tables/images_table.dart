import 'package:drift/drift.dart';
import 'package:koutu/data/local/database/converters/string_list_converter.dart';
import 'package:koutu/data/local/database/converters/map_converter.dart';

class Images extends Table {
  TextColumn get id => text()();
  TextColumn get userId => text()();
  TextColumn get garmentId => text().nullable()();
  TextColumn get wardrobeId => text().nullable()();
  TextColumn get originalUrl => text()();
  TextColumn get thumbnailUrl => text().nullable()();
  TextColumn get processedUrl => text().nullable()();
  TextColumn get backgroundRemovedUrl => text().nullable()();
  TextColumn get localPath => text().nullable()();
  TextColumn get filename => text()();
  TextColumn get mimeType => text()();
  IntColumn get fileSize => integer()();
  IntColumn get width => integer()();
  IntColumn get height => integer()();
  BoolColumn get isPrimary => boolean().withDefault(const Constant(false))();
  BoolColumn get isProcessed => boolean().withDefault(const Constant(false))();
  BoolColumn get isBackgroundRemoved => boolean().withDefault(const Constant(false))();
  TextColumn get processingStatus => text().nullable()();
  TextColumn get processingError => text().nullable()();
  TextColumn get colorPalette => text().map(const StringListConverter()).nullable()();
  TextColumn get dominantColor => text().nullable()();
  TextColumn get aiTags => text().map(const StringListConverter()).nullable()();
  TextColumn get metadata => text().map(const MapConverter()).nullable()();
  DateTimeColumn get createdAt => dateTime()();
  DateTimeColumn get updatedAt => dateTime()();
  DateTimeColumn get lastSyncedAt => dateTime().nullable()();

  @override
  Set<Column> get primaryKey => {id};
}