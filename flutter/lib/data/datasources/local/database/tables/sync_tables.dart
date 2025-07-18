import 'package:drift/drift.dart';

/// Sync queue table for tracking local changes
class SyncQueue extends Table {
  TextColumn get id => text()();
  TextColumn get entityId => text()();
  TextColumn get entityType => text()();
  TextColumn get operation => text()();
  TextColumn get data => text()();
  DateTimeColumn get timestamp => dateTime()();
  TextColumn get syncStatus => text()();
  IntColumn get retryCount => integer().withDefault(const Constant(0))();
  DateTimeColumn get syncedAt => dateTime().nullable()();
  
  @override
  Set<Column> get primaryKey => {id};
}

/// Backup records table
class BackupRecords extends Table {
  TextColumn get id => text()();
  TextColumn get backupId => text()();
  TextColumn get userId => text()();
  IntColumn get size => integer()();
  IntColumn get itemCount => integer()();
  TextColumn get description => text().nullable()();
  TextColumn get version => text()();
  DateTimeColumn get createdAt => dateTime()();
  
  @override
  Set<Column> get primaryKey => {id};
}

/// Session table for multi-device management
class Sessions extends Table {
  TextColumn get id => text()();
  TextColumn get userId => text()();
  TextColumn get deviceId => text()();
  TextColumn get deviceName => text()();
  TextColumn get deviceType => text()();
  TextColumn get fcmToken => text().nullable()();
  BoolColumn get isActive => boolean().withDefault(const Constant(true))();
  DateTimeColumn get lastActiveAt => dateTime()();
  DateTimeColumn get createdAt => dateTime()();
  
  @override
  Set<Column> get primaryKey => {id};
}

/// Analytics events table
class AnalyticsEvents extends Table {
  TextColumn get id => text()();
  TextColumn get userId => text()();
  TextColumn get eventType => text()();
  TextColumn get eventName => text()();
  TextColumn get properties => text().nullable()();
  DateTimeColumn get timestamp => dateTime()();
  BoolColumn get synced => boolean().withDefault(const Constant(false))();
  
  @override
  Set<Column> get primaryKey => {id};
}