import 'package:flutter/foundation.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:koutu/data/datasources/local/database/app_database.dart';
import 'package:koutu/services/cloud/cloud_storage_service.dart';
import 'package:koutu/services/auth/auth_service.dart';
import 'package:dartz/dartz.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'dart:convert';
import 'dart:async';

/// Manages automatic and manual backups
class BackupManager {
  final AppDatabase _database;
  final CloudStorageService _cloudStorage;
  final AuthService _authService;
  
  // Backup settings
  BackupSettings _settings = const BackupSettings();
  Timer? _autoBackupTimer;
  
  // Backup state
  bool _isBackingUp = false;
  DateTime? _lastBackupTime;
  
  // Stream controllers
  final _backupStatusController = StreamController<BackupStatus>.broadcast();
  final _backupProgressController = StreamController<BackupProgress>.broadcast();
  
  // Streams
  Stream<BackupStatus> get backupStatus => _backupStatusController.stream;
  Stream<BackupProgress> get backupProgress => _backupProgressController.stream;
  
  BackupManager({
    required AppDatabase database,
    required CloudStorageService cloudStorage,
    required AuthService authService,
  })  : _database = database,
        _cloudStorage = cloudStorage,
        _authService = authService;
  
  /// Initialize backup manager
  Future<void> initialize() async {
    await _loadSettings();
    await _loadLastBackupTime();
    
    if (_settings.autoBackupEnabled) {
      _scheduleAutoBackup();
    }
  }
  
  /// Perform manual backup
  Future<Either<Failure, CloudBackup>> performBackup({
    bool includeImages = true,
    String? description,
  }) async {
    if (_isBackingUp) {
      return Left(ServerFailure('Backup already in progress'));
    }
    
    _isBackingUp = true;
    _updateBackupStatus(BackupStatus.preparing);
    
    try {
      // Check if user is authenticated
      final isAuthenticated = await _authService.isAuthenticated();
      if (!isAuthenticated) {
        return Left(AuthFailure('User not authenticated'));
      }
      
      // Prepare backup data
      _updateProgress(0.1, 'Preparing backup data...');
      final backupData = await _prepareBackupData(includeImages);
      
      // Upload to cloud
      _updateProgress(0.3, 'Uploading backup...');
      _updateBackupStatus(BackupStatus.uploading);
      
      final result = await _cloudStorage.createBackup(
        backupData: backupData,
        onProgress: (progress) {
          _updateProgress(0.3 + (progress * 0.6), 'Uploading backup...');
        },
      );
      
      return result.fold(
        (failure) {
          _updateBackupStatus(BackupStatus.failed);
          return Left(failure);
        },
        (cloudBackup) async {
          // Update last backup time
          _lastBackupTime = DateTime.now();
          await _saveLastBackupTime();
          
          // Save backup record
          await _saveBackupRecord(cloudBackup, description);
          
          _updateProgress(1.0, 'Backup completed');
          _updateBackupStatus(BackupStatus.completed);
          
          return Right(cloudBackup);
        },
      );
    } catch (e) {
      _updateBackupStatus(BackupStatus.failed);
      return Left(ServerFailure('Backup failed: $e'));
    } finally {
      _isBackingUp = false;
    }
  }
  
  /// Restore from backup
  Future<Either<Failure, void>> restoreBackup({
    required String backupId,
    bool restoreImages = true,
  }) async {
    if (_isBackingUp) {
      return Left(ServerFailure('Operation in progress'));
    }
    
    _isBackingUp = true;
    _updateBackupStatus(BackupStatus.downloading);
    
    try {
      // Download backup
      _updateProgress(0.1, 'Downloading backup...');
      
      final result = await _cloudStorage.restoreBackup(
        backupId: backupId,
        onProgress: (progress) {
          _updateProgress(progress * 0.5, 'Downloading backup...');
        },
      );
      
      return result.fold(
        (failure) {
          _updateBackupStatus(BackupStatus.failed);
          return Left(failure);
        },
        (backupData) async {
          // Restore data
          _updateProgress(0.5, 'Restoring data...');
          _updateBackupStatus(BackupStatus.restoring);
          
          await _restoreBackupData(backupData, restoreImages);
          
          _updateProgress(1.0, 'Restore completed');
          _updateBackupStatus(BackupStatus.completed);
          
          return const Right(null);
        },
      );
    } catch (e) {
      _updateBackupStatus(BackupStatus.failed);
      return Left(ServerFailure('Restore failed: $e'));
    } finally {
      _isBackingUp = false;
    }
  }
  
  /// Get backup history
  Future<Either<Failure, List<BackupRecord>>> getBackupHistory() async {
    try {
      final records = await (_database.select(_database.backupRecords)
        ..orderBy([(tbl) => OrderingTerm(
          expression: tbl.createdAt,
          mode: OrderingMode.desc,
        )]))
        .get();
      
      final backupRecords = records.map((record) => BackupRecord(
        id: record.id,
        backupId: record.backupId,
        size: record.size,
        itemCount: record.itemCount,
        description: record.description,
        createdAt: record.createdAt,
        version: record.version,
      )).toList();
      
      return Right(backupRecords);
    } catch (e) {
      return Left(DatabaseFailure('Failed to get backup history: $e'));
    }
  }
  
  /// Update backup settings
  Future<Either<Failure, void>> updateSettings(BackupSettings settings) async {
    try {
      _settings = settings;
      await _saveSettings();
      
      // Update auto backup schedule
      if (settings.autoBackupEnabled) {
        _scheduleAutoBackup();
      } else {
        _autoBackupTimer?.cancel();
        _autoBackupTimer = null;
      }
      
      return const Right(null);
    } catch (e) {
      return Left(ServerFailure('Failed to update settings: $e'));
    }
  }
  
  /// Get backup settings
  BackupSettings getSettings() => _settings;
  
  /// Get last backup time
  DateTime? getLastBackupTime() => _lastBackupTime;
  
  /// Check if backup is needed
  bool isBackupNeeded() {
    if (_lastBackupTime == null) return true;
    
    final daysSinceBackup = DateTime.now().difference(_lastBackupTime!).inDays;
    
    switch (_settings.backupFrequency) {
      case BackupFrequency.daily:
        return daysSinceBackup >= 1;
      case BackupFrequency.weekly:
        return daysSinceBackup >= 7;
      case BackupFrequency.monthly:
        return daysSinceBackup >= 30;
      case BackupFrequency.manual:
        return false;
    }
  }
  
  // Private methods
  
  Future<BackupData> _prepareBackupData(bool includeImages) async {
    final data = <String, dynamic>{};
    
    // Export wardrobes
    final wardrobes = await _database.select(_database.wardrobes).get();
    data['wardrobes'] = wardrobes.map((w) => w.toJson()).toList();
    
    // Export garments
    final garments = await _database.select(_database.garments).get();
    data['garments'] = garments.map((g) => g.toJson()).toList();
    
    // Export outfits
    final outfits = await _database.select(_database.outfits).get();
    data['outfits'] = outfits.map((o) => o.toJson()).toList();
    
    // Export images metadata
    if (includeImages) {
      final images = await _database.select(_database.images).get();
      data['images'] = images.map((i) => i.toJson()).toList();
    }
    
    // Export user preferences
    final prefs = await SharedPreferences.getInstance();
    data['preferences'] = {
      'theme': prefs.getString('theme'),
      'language': prefs.getString('language'),
      'notifications': prefs.getBool('notifications'),
    };
    
    final totalItems = (data['wardrobes'] as List).length +
                      (data['garments'] as List).length +
                      (data['outfits'] as List).length;
    
    return BackupData(
      version: '1.0',
      createdAt: DateTime.now(),
      totalItems: totalItems,
      data: data,
    );
  }
  
  Future<void> _restoreBackupData(BackupData backupData, bool restoreImages) async {
    // Clear existing data (optional - could merge instead)
    if (_settings.clearDataBeforeRestore) {
      await _database.transaction(() async {
        await _database.delete(_database.outfits).go();
        await _database.delete(_database.garments).go();
        await _database.delete(_database.wardrobes).go();
        if (restoreImages) {
          await _database.delete(_database.images).go();
        }
      });
    }
    
    // Restore data in correct order due to foreign keys
    await _database.transaction(() async {
      // Restore wardrobes
      if (backupData.data['wardrobes'] != null) {
        for (final json in backupData.data['wardrobes']) {
          await _database.into(_database.wardrobes).insertOnConflictUpdate(
            WardrobesCompanion.fromJson(json),
          );
        }
      }
      
      // Restore garments
      if (backupData.data['garments'] != null) {
        for (final json in backupData.data['garments']) {
          await _database.into(_database.garments).insertOnConflictUpdate(
            GarmentsCompanion.fromJson(json),
          );
        }
      }
      
      // Restore outfits
      if (backupData.data['outfits'] != null) {
        for (final json in backupData.data['outfits']) {
          await _database.into(_database.outfits).insertOnConflictUpdate(
            OutfitsCompanion.fromJson(json),
          );
        }
      }
      
      // Restore images
      if (restoreImages && backupData.data['images'] != null) {
        for (final json in backupData.data['images']) {
          await _database.into(_database.images).insertOnConflictUpdate(
            ImagesCompanion.fromJson(json),
          );
        }
      }
    });
    
    // Restore preferences
    if (backupData.data['preferences'] != null) {
      final prefs = await SharedPreferences.getInstance();
      final preferences = backupData.data['preferences'];
      
      if (preferences['theme'] != null) {
        await prefs.setString('theme', preferences['theme']);
      }
      if (preferences['language'] != null) {
        await prefs.setString('language', preferences['language']);
      }
      if (preferences['notifications'] != null) {
        await prefs.setBool('notifications', preferences['notifications']);
      }
    }
  }
  
  void _scheduleAutoBackup() {
    _autoBackupTimer?.cancel();
    
    if (!_settings.autoBackupEnabled) return;
    
    // Calculate next backup time
    final now = DateTime.now();
    DateTime nextBackup;
    
    switch (_settings.backupFrequency) {
      case BackupFrequency.daily:
        nextBackup = DateTime(now.year, now.month, now.day + 1, 2, 0);
        break;
      case BackupFrequency.weekly:
        final daysUntilNextWeek = 7 - now.weekday + 1;
        nextBackup = DateTime(now.year, now.month, now.day + daysUntilNextWeek, 2, 0);
        break;
      case BackupFrequency.monthly:
        nextBackup = DateTime(now.year, now.month + 1, 1, 2, 0);
        break;
      case BackupFrequency.manual:
        return;
    }
    
    final duration = nextBackup.difference(now);
    
    _autoBackupTimer = Timer(duration, () async {
      if (_settings.autoBackupEnabled) {
        await performBackup(
          includeImages: _settings.includeImages,
          description: 'Automatic backup',
        );
        
        // Schedule next backup
        _scheduleAutoBackup();
      }
    });
  }
  
  Future<void> _saveBackupRecord(CloudBackup backup, String? description) async {
    await _database.into(_database.backupRecords).insert(
      BackupRecordsCompanion.insert(
        backupId: backup.id,
        userId: backup.userId,
        size: backup.size,
        itemCount: backup.metadata['itemCount'] ?? 0,
        description: Value(description),
        version: backup.version,
        createdAt: backup.createdAt,
      ),
    );
  }
  
  Future<void> _loadSettings() async {
    final prefs = await SharedPreferences.getInstance();
    final settingsJson = prefs.getString('backup_settings');
    
    if (settingsJson != null) {
      _settings = BackupSettings.fromJson(json.decode(settingsJson));
    }
  }
  
  Future<void> _saveSettings() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('backup_settings', json.encode(_settings.toJson()));
  }
  
  Future<void> _loadLastBackupTime() async {
    final prefs = await SharedPreferences.getInstance();
    final timeString = prefs.getString('last_backup_time');
    
    if (timeString != null) {
      _lastBackupTime = DateTime.parse(timeString);
    }
  }
  
  Future<void> _saveLastBackupTime() async {
    if (_lastBackupTime != null) {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString('last_backup_time', _lastBackupTime!.toIso8601String());
    }
  }
  
  void _updateBackupStatus(BackupStatus status) {
    _backupStatusController.add(status);
  }
  
  void _updateProgress(double progress, String message) {
    _backupProgressController.add(BackupProgress(
      progress: progress,
      message: message,
    ));
  }
  
  void dispose() {
    _autoBackupTimer?.cancel();
    _backupStatusController.close();
    _backupProgressController.close();
  }
}

/// Backup settings
class BackupSettings {
  final bool autoBackupEnabled;
  final BackupFrequency backupFrequency;
  final bool includeImages;
  final bool wifiOnly;
  final bool clearDataBeforeRestore;
  final int maxBackupCount;
  
  const BackupSettings({
    this.autoBackupEnabled = true,
    this.backupFrequency = BackupFrequency.weekly,
    this.includeImages = true,
    this.wifiOnly = true,
    this.clearDataBeforeRestore = false,
    this.maxBackupCount = 10,
  });
  
  Map<String, dynamic> toJson() => {
    'autoBackupEnabled': autoBackupEnabled,
    'backupFrequency': backupFrequency.name,
    'includeImages': includeImages,
    'wifiOnly': wifiOnly,
    'clearDataBeforeRestore': clearDataBeforeRestore,
    'maxBackupCount': maxBackupCount,
  };
  
  factory BackupSettings.fromJson(Map<String, dynamic> json) {
    return BackupSettings(
      autoBackupEnabled: json['autoBackupEnabled'] ?? true,
      backupFrequency: BackupFrequency.values.firstWhere(
        (f) => f.name == json['backupFrequency'],
        orElse: () => BackupFrequency.weekly,
      ),
      includeImages: json['includeImages'] ?? true,
      wifiOnly: json['wifiOnly'] ?? true,
      clearDataBeforeRestore: json['clearDataBeforeRestore'] ?? false,
      maxBackupCount: json['maxBackupCount'] ?? 10,
    );
  }
  
  BackupSettings copyWith({
    bool? autoBackupEnabled,
    BackupFrequency? backupFrequency,
    bool? includeImages,
    bool? wifiOnly,
    bool? clearDataBeforeRestore,
    int? maxBackupCount,
  }) {
    return BackupSettings(
      autoBackupEnabled: autoBackupEnabled ?? this.autoBackupEnabled,
      backupFrequency: backupFrequency ?? this.backupFrequency,
      includeImages: includeImages ?? this.includeImages,
      wifiOnly: wifiOnly ?? this.wifiOnly,
      clearDataBeforeRestore: clearDataBeforeRestore ?? this.clearDataBeforeRestore,
      maxBackupCount: maxBackupCount ?? this.maxBackupCount,
    );
  }
}

/// Backup frequency
enum BackupFrequency {
  daily,
  weekly,
  monthly,
  manual,
}

/// Backup status
enum BackupStatus {
  idle,
  preparing,
  uploading,
  downloading,
  restoring,
  completed,
  failed,
}

/// Backup progress
class BackupProgress {
  final double progress;
  final String message;
  
  const BackupProgress({
    required this.progress,
    required this.message,
  });
}

/// Backup record
class BackupRecord {
  final String id;
  final String backupId;
  final int size;
  final int itemCount;
  final String? description;
  final DateTime createdAt;
  final String version;
  
  const BackupRecord({
    required this.id,
    required this.backupId,
    required this.size,
    required this.itemCount,
    this.description,
    required this.createdAt,
    required this.version,
  });
}