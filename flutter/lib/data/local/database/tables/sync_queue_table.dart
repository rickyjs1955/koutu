import 'package:drift/drift.dart';
import 'package:koutu/data/local/database/converters/map_converter.dart';

enum SyncOperation {
  create,
  update,
  delete,
}

enum SyncStatus {
  pending,
  inProgress,
  completed,
  failed,
}

class SyncQueue extends Table {
  IntColumn get id => integer().autoIncrement()();
  TextColumn get operation => textEnum<SyncOperation>()();
  TextColumn get entityType => text()();
  TextColumn get entityId => text()();
  TextColumn get userId => text().nullable()();
  TextColumn get wardrobeId => text().nullable()();
  TextColumn get garmentId => text().nullable()();
  TextColumn get payload => text().map(const MapConverter())();
  TextColumn get status => textEnum<SyncStatus>().withDefault(const Constant(SyncStatus.pending))();
  IntColumn get retryCount => integer().withDefault(const Constant(0))();
  TextColumn get lastError => text().nullable()();
  DateTimeColumn get createdAt => dateTime()();
  DateTimeColumn get updatedAt => dateTime()();
  DateTimeColumn get scheduledAt => dateTime().nullable()();

  @override
  Set<Column> get primaryKey => {id};
}