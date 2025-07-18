import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:koutu/services/security/encryption_service.dart';
import 'package:koutu/services/security/data_sanitization_service.dart';
import 'package:koutu/data/datasources/local/database/app_database.dart';
import 'package:dartz/dartz.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:path_provider/path_provider.dart';
import 'package:crypto/crypto.dart';

/// Service for secure cloud backup with encryption
class SecureBackupService {
  final EncryptionService _encryptionService;
  final DataSanitizationService _sanitizationService;
  final AppDatabase _database;
  final SharedPreferences _preferences;
  
  // Backup settings
  static const String _backupEnabledKey = 'backup_enabled';
  static const String _autoBackupKey = 'auto_backup_enabled';
  static const String _backupFrequencyKey = 'backup_frequency';
  static const String _lastBackupKey = 'last_backup_time';
  static const String _backupSizeKey = 'backup_size';
  
  SecureBackupService({
    required EncryptionService encryptionService,
    required DataSanitizationService sanitizationService,
    required AppDatabase database,
    required SharedPreferences preferences,
  })  : _encryptionService = encryptionService,
        _sanitizationService = sanitizationService,
        _database = database,
        _preferences = preferences;
  
  /// Create encrypted backup
  Future<Either<Failure, BackupResult>> createBackup({
    required BackupOptions options,
    void Function(double progress)? onProgress,
  }) async {
    try {
      onProgress?.call(0.0);
      
      // Collect data to backup
      final backupData = await _collectBackupData(options);
      onProgress?.call(0.2);
      
      // Sanitize data if required
      final sanitizedData = options.sanitizeData
          ? _sanitizationService.sanitizeData(
              backupData,
              level: options.sanitizationLevel,
            )
          : Right(backupData);
      
      return sanitizedData.fold(
        (failure) => Left(failure),
        (data) async {
          onProgress?.call(0.4);
          
          // Create backup manifest
          final manifest = BackupManifest(
            version: '1.0',
            createdAt: DateTime.now(),
            deviceId: await _getDeviceId(),
            appVersion: '1.0.0', // Get from package info
            dataTypes: _getDataTypes(data),
            isEncrypted: true,
            checksum: '',
          );
          
          // Combine manifest and data
          final backupContent = {
            'manifest': manifest.toJson(),
            'data': data,
          };
          
          onProgress?.call(0.6);
          
          // Encrypt backup content
          final encryptedResult = await _encryptionService.encryptJson(backupContent);
          
          return encryptedResult.fold(
            (failure) => Left(failure),
            (encrypted) async {
              onProgress?.call(0.8);
              
              // Generate checksum
              final checksum = _generateChecksum(encrypted);
              
              // Create backup file
              final backupFile = await _createBackupFile(
                encrypted,
                checksum,
                options.includeImages,
              );
              
              onProgress?.call(0.9);
              
              // Save backup metadata
              await _saveBackupMetadata(backupFile, manifest);
              
              onProgress?.call(1.0);
              
              return Right(BackupResult(
                success: true,
                backupFile: backupFile,
                manifest: manifest,
                size: backupFile.lengthSync(),
              ));
            },
          );
        },
      );
    } catch (e) {
      return Left(BackupFailure('Failed to create backup: $e'));
    }
  }
  
  /// Restore from encrypted backup
  Future<Either<Failure, RestoreResult>> restoreBackup({
    required File backupFile,
    required BackupOptions options,
    void Function(double progress)? onProgress,
  }) async {
    try {
      onProgress?.call(0.0);
      
      // Validate backup file
      final validateResult = await _validateBackupFile(backupFile);
      
      return validateResult.fold(
        (failure) => Left(failure),
        (isValid) async {
          if (!isValid) {
            return Left(BackupFailure('Invalid backup file'));
          }
          
          onProgress?.call(0.2);
          
          // Read and decrypt backup
          final encrypted = await backupFile.readAsString();
          final decryptedResult = await _encryptionService.decryptJson(encrypted);
          
          return decryptedResult.fold(
            (failure) => Left(failure),
            (decrypted) async {
              onProgress?.call(0.4);
              
              // Parse manifest and data
              final manifest = BackupManifest.fromJson(decrypted['manifest']);
              final data = decrypted['data'] as Map<String, dynamic>;
              
              onProgress?.call(0.6);
              
              // Restore data
              final restoreResult = await _restoreData(data, options);
              
              return restoreResult.fold(
                (failure) => Left(failure),
                (restored) async {
                  onProgress?.call(0.8);
                  
                  // Update metadata
                  await _updateRestoreMetadata(manifest);
                  
                  onProgress?.call(1.0);
                  
                  return Right(RestoreResult(
                    success: true,
                    manifest: manifest,
                    restoredItems: restored,
                  ));
                },
              );
            },
          );
        },
      );
    } catch (e) {
      return Left(BackupFailure('Failed to restore backup: $e'));
    }
  }
  
  /// Export backup to file
  Future<Either<Failure, File>> exportBackup({
    required BackupOptions options,
    String? customPath,
  }) async {
    try {
      // Create backup
      final backupResult = await createBackup(options: options);
      
      return backupResult.fold(
        (failure) => Left(failure),
        (result) async {
          final backupFile = result.backupFile;
          
          if (customPath != null) {
            // Copy to custom location
            final customFile = File(customPath);
            await backupFile.copy(customFile.path);
            return Right(customFile);
          }
          
          return Right(backupFile);
        },
      );
    } catch (e) {
      return Left(BackupFailure('Failed to export backup: $e'));
    }
  }
  
  /// Get backup history
  Future<Either<Failure, List<BackupInfo>>> getBackupHistory() async {
    try {
      final backupHistory = <BackupInfo>[];
      
      // Get backup directory
      final backupDir = await _getBackupDirectory();
      if (!backupDir.existsSync()) {
        return Right(backupHistory);
      }
      
      // List backup files
      final files = backupDir.listSync().whereType<File>().toList();
      
      for (final file in files) {
        if (file.path.endsWith('.backup')) {
          final info = await _getBackupInfo(file);
          if (info != null) {
            backupHistory.add(info);
          }
        }
      }
      
      // Sort by creation date (newest first)
      backupHistory.sort((a, b) => b.createdAt.compareTo(a.createdAt));
      
      return Right(backupHistory);
    } catch (e) {
      return Left(BackupFailure('Failed to get backup history: $e'));
    }
  }
  
  /// Delete backup
  Future<Either<Failure, void>> deleteBackup(String backupId) async {
    try {
      final backupDir = await _getBackupDirectory();
      final backupFile = File('${backupDir.path}/$backupId.backup');
      
      if (backupFile.existsSync()) {
        await backupFile.delete();
      }
      
      return const Right(null);
    } catch (e) {
      return Left(BackupFailure('Failed to delete backup: $e'));
    }
  }
  
  /// Schedule automatic backup
  Future<Either<Failure, void>> scheduleAutoBackup({
    required BackupFrequency frequency,
    required BackupOptions options,
  }) async {
    try {
      await _preferences.setBool(_autoBackupKey, true);
      await _preferences.setString(_backupFrequencyKey, frequency.name);
      
      // Schedule next backup
      await _scheduleNextBackup(frequency, options);
      
      return const Right(null);
    } catch (e) {
      return Left(BackupFailure('Failed to schedule auto backup: $e'));
    }
  }
  
  /// Get backup settings
  BackupSettings getSettings() {
    return BackupSettings(
      isEnabled: _preferences.getBool(_backupEnabledKey) ?? false,
      autoBackup: _preferences.getBool(_autoBackupKey) ?? false,
      frequency: BackupFrequency.values.firstWhere(
        (f) => f.name == _preferences.getString(_backupFrequencyKey),
        orElse: () => BackupFrequency.weekly,
      ),
      lastBackup: _preferences.getString(_lastBackupKey) != null
          ? DateTime.parse(_preferences.getString(_lastBackupKey)!)
          : null,
      totalBackupSize: _preferences.getInt(_backupSizeKey) ?? 0,
    );
  }
  
  /// Update backup settings
  Future<Either<Failure, void>> updateSettings(BackupSettings settings) async {
    try {
      await _preferences.setBool(_backupEnabledKey, settings.isEnabled);
      await _preferences.setBool(_autoBackupKey, settings.autoBackup);
      await _preferences.setString(_backupFrequencyKey, settings.frequency.name);
      
      return const Right(null);
    } catch (e) {
      return Left(BackupFailure('Failed to update settings: $e'));
    }
  }
  
  // Private methods
  
  Future<Map<String, dynamic>> _collectBackupData(BackupOptions options) async {
    final data = <String, dynamic>{};
    
    // Collect garments
    if (options.includeGarments) {
      final garments = await _database.select(_database.garments).get();
      data['garments'] = garments.map((g) => g.toJson()).toList();
    }
    
    // Collect outfits
    if (options.includeOutfits) {
      final outfits = await _database.select(_database.outfits).get();
      data['outfits'] = outfits.map((o) => o.toJson()).toList();
    }
    
    // Collect preferences
    if (options.includePreferences) {
      final prefs = <String, dynamic>{};
      for (final key in _preferences.getKeys()) {
        if (!key.startsWith('secure_') && !key.startsWith('encrypted_')) {
          prefs[key] = _preferences.get(key);
        }
      }
      data['preferences'] = prefs;
    }
    
    // Collect analytics (anonymized)
    if (options.includeAnalytics) {
      // This would collect anonymized analytics data
      data['analytics'] = {};
    }
    
    return data;
  }
  
  String _generateChecksum(String data) {
    final bytes = utf8.encode(data);
    final digest = sha256.convert(bytes);
    return digest.toString();
  }
  
  Future<File> _createBackupFile(
    String encrypted,
    String checksum,
    bool includeImages,
  ) async {
    final backupDir = await _getBackupDirectory();
    if (!backupDir.existsSync()) {
      await backupDir.create(recursive: true);
    }
    
    final timestamp = DateTime.now().millisecondsSinceEpoch;
    final backupFile = File('${backupDir.path}/backup_$timestamp.backup');
    
    // Create backup content with checksum
    final backupContent = {
      'checksum': checksum,
      'data': encrypted,
    };
    
    await backupFile.writeAsString(json.encode(backupContent));
    
    return backupFile;
  }
  
  Future<bool> _validateBackupFile(File backupFile) async {
    try {
      final content = await backupFile.readAsString();
      final backupData = json.decode(content);
      
      // Check required fields
      if (!backupData.containsKey('checksum') || 
          !backupData.containsKey('data')) {
        return false;
      }
      
      // Verify checksum
      final storedChecksum = backupData['checksum'];
      final data = backupData['data'];
      final calculatedChecksum = _generateChecksum(data);
      
      return storedChecksum == calculatedChecksum;
    } catch (e) {
      return false;
    }
  }
  
  Future<Either<Failure, Map<String, int>>> _restoreData(
    Map<String, dynamic> data,
    BackupOptions options,
  ) async {
    try {
      final restored = <String, int>{};
      
      // Restore garments
      if (options.includeGarments && data.containsKey('garments')) {
        final garments = data['garments'] as List<dynamic>;
        int count = 0;
        
        for (final garmentData in garments) {
          // Convert and insert garment
          // This would need proper conversion from JSON to Garment object
          count++;
        }
        
        restored['garments'] = count;
      }
      
      // Restore outfits
      if (options.includeOutfits && data.containsKey('outfits')) {
        final outfits = data['outfits'] as List<dynamic>;
        restored['outfits'] = outfits.length;
      }
      
      // Restore preferences
      if (options.includePreferences && data.containsKey('preferences')) {
        final prefs = data['preferences'] as Map<String, dynamic>;
        int count = 0;
        
        for (final entry in prefs.entries) {
          await _preferences.setString(entry.key, entry.value.toString());
          count++;
        }
        
        restored['preferences'] = count;
      }
      
      return Right(restored);
    } catch (e) {
      return Left(BackupFailure('Failed to restore data: $e'));
    }
  }
  
  Future<Directory> _getBackupDirectory() async {
    final appDir = await getApplicationDocumentsDirectory();
    return Directory('${appDir.path}/backups');
  }
  
  Future<String> _getDeviceId() async {
    // Generate or retrieve device ID
    const key = 'device_id';
    String? deviceId = _preferences.getString(key);
    
    if (deviceId == null) {
      deviceId = DateTime.now().millisecondsSinceEpoch.toString();
      await _preferences.setString(key, deviceId);
    }
    
    return deviceId;
  }
  
  List<String> _getDataTypes(Map<String, dynamic> data) {
    return data.keys.toList();
  }
  
  Future<void> _saveBackupMetadata(File backupFile, BackupManifest manifest) async {
    await _preferences.setString(_lastBackupKey, DateTime.now().toIso8601String());
    await _preferences.setInt(_backupSizeKey, backupFile.lengthSync());
  }
  
  Future<void> _updateRestoreMetadata(BackupManifest manifest) async {
    // Update restore metadata
    await _preferences.setString('last_restore_time', DateTime.now().toIso8601String());
    await _preferences.setString('restore_version', manifest.version);
  }
  
  Future<BackupInfo?> _getBackupInfo(File backupFile) async {
    try {
      final content = await backupFile.readAsString();
      final backupData = json.decode(content);
      
      if (backupData.containsKey('data')) {
        final encrypted = backupData['data'];
        final decrypted = await _encryptionService.decryptJson(encrypted);
        
        return decrypted.fold(
          (failure) => null,
          (data) {
            if (data.containsKey('manifest')) {
              final manifest = BackupManifest.fromJson(data['manifest']);
              return BackupInfo(
                id: backupFile.path.split('/').last.replaceAll('.backup', ''),
                createdAt: manifest.createdAt,
                size: backupFile.lengthSync(),
                version: manifest.version,
                dataTypes: manifest.dataTypes,
              );
            }
            return null;
          },
        );
      }
      
      return null;
    } catch (e) {
      return null;
    }
  }
  
  Future<void> _scheduleNextBackup(
    BackupFrequency frequency,
    BackupOptions options,
  ) async {
    // This would integrate with a background task scheduler
    // For now, just save the schedule
    await _preferences.setString('next_backup_options', json.encode(options.toJson()));
  }
}

/// Backup options
class BackupOptions {
  final bool includeGarments;
  final bool includeOutfits;
  final bool includePreferences;
  final bool includeAnalytics;
  final bool includeImages;
  final bool sanitizeData;
  final SanitizationLevel sanitizationLevel;
  
  const BackupOptions({
    this.includeGarments = true,
    this.includeOutfits = true,
    this.includePreferences = true,
    this.includeAnalytics = false,
    this.includeImages = false,
    this.sanitizeData = true,
    this.sanitizationLevel = SanitizationLevel.standard,
  });
  
  Map<String, dynamic> toJson() => {
    'includeGarments': includeGarments,
    'includeOutfits': includeOutfits,
    'includePreferences': includePreferences,
    'includeAnalytics': includeAnalytics,
    'includeImages': includeImages,
    'sanitizeData': sanitizeData,
    'sanitizationLevel': sanitizationLevel.name,
  };
  
  factory BackupOptions.fromJson(Map<String, dynamic> json) {
    return BackupOptions(
      includeGarments: json['includeGarments'] ?? true,
      includeOutfits: json['includeOutfits'] ?? true,
      includePreferences: json['includePreferences'] ?? true,
      includeAnalytics: json['includeAnalytics'] ?? false,
      includeImages: json['includeImages'] ?? false,
      sanitizeData: json['sanitizeData'] ?? true,
      sanitizationLevel: SanitizationLevel.values.firstWhere(
        (l) => l.name == json['sanitizationLevel'],
        orElse: () => SanitizationLevel.standard,
      ),
    );
  }
}

/// Backup manifest
class BackupManifest {
  final String version;
  final DateTime createdAt;
  final String deviceId;
  final String appVersion;
  final List<String> dataTypes;
  final bool isEncrypted;
  final String checksum;
  
  const BackupManifest({
    required this.version,
    required this.createdAt,
    required this.deviceId,
    required this.appVersion,
    required this.dataTypes,
    required this.isEncrypted,
    required this.checksum,
  });
  
  Map<String, dynamic> toJson() => {
    'version': version,
    'createdAt': createdAt.toIso8601String(),
    'deviceId': deviceId,
    'appVersion': appVersion,
    'dataTypes': dataTypes,
    'isEncrypted': isEncrypted,
    'checksum': checksum,
  };
  
  factory BackupManifest.fromJson(Map<String, dynamic> json) {
    return BackupManifest(
      version: json['version'],
      createdAt: DateTime.parse(json['createdAt']),
      deviceId: json['deviceId'],
      appVersion: json['appVersion'],
      dataTypes: List<String>.from(json['dataTypes']),
      isEncrypted: json['isEncrypted'],
      checksum: json['checksum'],
    );
  }
}

/// Backup result
class BackupResult {
  final bool success;
  final File backupFile;
  final BackupManifest manifest;
  final int size;
  
  const BackupResult({
    required this.success,
    required this.backupFile,
    required this.manifest,
    required this.size,
  });
}

/// Restore result
class RestoreResult {
  final bool success;
  final BackupManifest manifest;
  final Map<String, int> restoredItems;
  
  const RestoreResult({
    required this.success,
    required this.manifest,
    required this.restoredItems,
  });
}

/// Backup info
class BackupInfo {
  final String id;
  final DateTime createdAt;
  final int size;
  final String version;
  final List<String> dataTypes;
  
  const BackupInfo({
    required this.id,
    required this.createdAt,
    required this.size,
    required this.version,
    required this.dataTypes,
  });
}

/// Backup settings
class BackupSettings {
  final bool isEnabled;
  final bool autoBackup;
  final BackupFrequency frequency;
  final DateTime? lastBackup;
  final int totalBackupSize;
  
  const BackupSettings({
    required this.isEnabled,
    required this.autoBackup,
    required this.frequency,
    this.lastBackup,
    required this.totalBackupSize,
  });
}

/// Backup frequency
enum BackupFrequency {
  daily,
  weekly,
  monthly,
}

/// Backup failure
class BackupFailure extends Failure {
  const BackupFailure(String message) : super(message);
}