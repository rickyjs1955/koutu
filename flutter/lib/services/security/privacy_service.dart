import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:koutu/services/security/data_sanitization_service.dart';
import 'package:koutu/services/security/secure_storage_service.dart';
import 'package:koutu/data/datasources/local/database/app_database.dart';
import 'package:dartz/dartz.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:crypto/crypto.dart';

/// Service for privacy-focused data handling and user privacy controls
class PrivacyService {
  final DataSanitizationService _sanitizationService;
  final SecureStorageService _secureStorage;
  final AppDatabase _database;
  final SharedPreferences _preferences;
  
  // Privacy settings keys
  static const String _privacyPolicyAcceptedKey = 'privacy_policy_accepted';
  static const String _dataCollectionConsentKey = 'data_collection_consent';
  static const String _analyticsConsentKey = 'analytics_consent';
  static const String _marketingConsentKey = 'marketing_consent';
  static const String _dataRetentionPeriodKey = 'data_retention_period';
  static const String _lastPrivacyUpdateKey = 'last_privacy_update';
  static const String _privacyAuditLogKey = 'privacy_audit_log';
  static const String _dataExportRequestKey = 'data_export_request';
  static const String _dataDeletionRequestKey = 'data_deletion_request';
  
  PrivacyService({
    required DataSanitizationService sanitizationService,
    required SecureStorageService secureStorage,
    required AppDatabase database,
    required SharedPreferences preferences,
  })  : _sanitizationService = sanitizationService,
        _secureStorage = secureStorage,
        _database = database,
        _preferences = preferences;
  
  /// Get current privacy settings
  PrivacySettings getPrivacySettings() {
    return PrivacySettings(
      privacyPolicyAccepted: _preferences.getBool(_privacyPolicyAcceptedKey) ?? false,
      dataCollectionConsent: _preferences.getBool(_dataCollectionConsentKey) ?? false,
      analyticsConsent: _preferences.getBool(_analyticsConsentKey) ?? false,
      marketingConsent: _preferences.getBool(_marketingConsentKey) ?? false,
      dataRetentionPeriod: DataRetentionPeriod.values.firstWhere(
        (p) => p.name == _preferences.getString(_dataRetentionPeriodKey),
        orElse: () => DataRetentionPeriod.twoYears,
      ),
      lastPrivacyUpdate: _preferences.getString(_lastPrivacyUpdateKey) != null
          ? DateTime.parse(_preferences.getString(_lastPrivacyUpdateKey)!)
          : null,
    );
  }
  
  /// Update privacy settings
  Future<Either<Failure, void>> updatePrivacySettings(PrivacySettings settings) async {
    try {
      await _preferences.setBool(_privacyPolicyAcceptedKey, settings.privacyPolicyAccepted);
      await _preferences.setBool(_dataCollectionConsentKey, settings.dataCollectionConsent);
      await _preferences.setBool(_analyticsConsentKey, settings.analyticsConsent);
      await _preferences.setBool(_marketingConsentKey, settings.marketingConsent);
      await _preferences.setString(_dataRetentionPeriodKey, settings.dataRetentionPeriod.name);
      await _preferences.setString(_lastPrivacyUpdateKey, DateTime.now().toIso8601String());
      
      // Log privacy settings change
      await _logPrivacyAction(
        PrivacyAction.settingsUpdated,
        'Privacy settings updated',
        {'timestamp': DateTime.now().toIso8601String()},
      );
      
      return const Right(null);
    } catch (e) {
      return Left(SecurityFailure('Failed to update privacy settings: $e'));
    }
  }
  
  /// Accept privacy policy
  Future<Either<Failure, void>> acceptPrivacyPolicy(String version) async {
    try {
      await _preferences.setBool(_privacyPolicyAcceptedKey, true);
      await _preferences.setString(_lastPrivacyUpdateKey, DateTime.now().toIso8601String());
      
      // Log privacy policy acceptance
      await _logPrivacyAction(
        PrivacyAction.privacyPolicyAccepted,
        'Privacy policy accepted',
        {'version': version, 'timestamp': DateTime.now().toIso8601String()},
      );
      
      return const Right(null);
    } catch (e) {
      return Left(SecurityFailure('Failed to accept privacy policy: $e'));
    }
  }
  
  /// Request data export (GDPR Article 20)
  Future<Either<Failure, DataExportResult>> requestDataExport(DataExportRequest request) async {
    try {
      // Log data export request
      await _logPrivacyAction(
        PrivacyAction.dataExportRequested,
        'Data export requested',
        {
          'format': request.format.name,
          'includePersonalData': request.includePersonalData,
          'includePurchaseHistory': request.includePurchaseHistory,
          'includeAnalytics': request.includeAnalytics,
          'timestamp': DateTime.now().toIso8601String(),
        },
      );
      
      // Collect user data
      final userData = await _collectUserData(request);
      
      // Create privacy-compliant export
      final exportResult = _sanitizationService.createPrivacyCompliantExport(
        userData,
        includePersonalData: request.includePersonalData,
        includeAnalytics: request.includeAnalytics,
        includePurchaseHistory: request.includePurchaseHistory,
      );
      
      return exportResult.fold(
        (failure) => Left(failure),
        (exportData) async {
          // Store export request
          await _storeExportRequest(request, exportData);
          
          return Right(DataExportResult(
            exportId: _generateExportId(),
            format: request.format,
            data: exportData,
            size: json.encode(exportData).length,
            createdAt: DateTime.now(),
          ));
        },
      );
    } catch (e) {
      return Left(SecurityFailure('Failed to export data: $e'));
    }
  }
  
  /// Request data deletion (GDPR Article 17 - Right to be forgotten)
  Future<Either<Failure, DataDeletionResult>> requestDataDeletion(DataDeletionRequest request) async {
    try {
      // Log data deletion request
      await _logPrivacyAction(
        PrivacyAction.dataDeletionRequested,
        'Data deletion requested',
        {
          'deletePersonalData': request.deletePersonalData,
          'deleteAppData': request.deleteAppData,
          'deleteAnalytics': request.deleteAnalytics,
          'reason': request.reason,
          'timestamp': DateTime.now().toIso8601String(),
        },
      );
      
      final deletionSummary = <String, int>{};
      
      // Delete personal data
      if (request.deletePersonalData) {
        final personalDataResult = await _deletePersonalData();
        personalDataResult.fold(
          (failure) => throw failure,
          (count) => deletionSummary['personalData'] = count,
        );
      }
      
      // Delete app data
      if (request.deleteAppData) {
        final appDataResult = await _deleteAppData();
        appDataResult.fold(
          (failure) => throw failure,
          (count) => deletionSummary['appData'] = count,
        );
      }
      
      // Delete analytics data
      if (request.deleteAnalytics) {
        final analyticsResult = await _deleteAnalyticsData();
        analyticsResult.fold(
          (failure) => throw failure,
          (count) => deletionSummary['analytics'] = count,
        );
      }
      
      // Store deletion request
      await _storeDeletionRequest(request, deletionSummary);
      
      return Right(DataDeletionResult(
        deletionId: _generateDeletionId(),
        deletedItems: deletionSummary,
        completedAt: DateTime.now(),
      ));
    } catch (e) {
      return Left(SecurityFailure('Failed to delete data: $e'));
    }
  }
  
  /// Get privacy audit log
  Future<Either<Failure, List<PrivacyAuditEntry>>> getPrivacyAuditLog() async {
    try {
      final logResult = await _secureStorage.getSecureString(
        key: _privacyAuditLogKey,
        useSecureStorage: true,
      );
      
      return logResult.fold(
        (failure) => Left(failure),
        (logJson) {
          if (logJson == null) {
            return const Right([]);
          }
          
          final logData = json.decode(logJson) as List<dynamic>;
          final entries = logData.map((entry) => PrivacyAuditEntry.fromJson(entry)).toList();
          
          return Right(entries);
        },
      );
    } catch (e) {
      return Left(SecurityFailure('Failed to get privacy audit log: $e'));
    }
  }
  
  /// Check data retention compliance
  Future<Either<Failure, DataRetentionReport>> checkDataRetentionCompliance() async {
    try {
      final settings = getPrivacySettings();
      final retentionPeriod = settings.dataRetentionPeriod;
      final cutoffDate = DateTime.now().subtract(_getRetentionDuration(retentionPeriod));
      
      final report = DataRetentionReport(
        retentionPeriod: retentionPeriod,
        cutoffDate: cutoffDate,
        itemsToDelete: [],
        complianceStatus: ComplianceStatus.compliant,
        checkDate: DateTime.now(),
      );
      
      // Check garments older than retention period
      final oldGarments = await _database.select(_database.garments)
          .where((g) => g.createdAt.isSmallerThanValue(cutoffDate))
          .get();
      
      if (oldGarments.isNotEmpty) {
        report.itemsToDelete.addAll(
          oldGarments.map((g) => RetentionItem(
            id: g.id,
            type: 'garment',
            createdAt: g.createdAt,
            description: g.name,
          )),
        );
        report.complianceStatus = ComplianceStatus.actionRequired;
      }
      
      // Check outfits older than retention period
      final oldOutfits = await _database.select(_database.outfits)
          .where((o) => o.createdAt.isSmallerThanValue(cutoffDate))
          .get();
      
      if (oldOutfits.isNotEmpty) {
        report.itemsToDelete.addAll(
          oldOutfits.map((o) => RetentionItem(
            id: o.id,
            type: 'outfit',
            createdAt: o.createdAt,
            description: o.name,
          )),
        );
        report.complianceStatus = ComplianceStatus.actionRequired;
      }
      
      return Right(report);
    } catch (e) {
      return Left(SecurityFailure('Failed to check data retention compliance: $e'));
    }
  }
  
  /// Enforce data retention policy
  Future<Either<Failure, DataRetentionResult>> enforceDataRetentionPolicy() async {
    try {
      final complianceResult = await checkDataRetentionCompliance();
      
      return complianceResult.fold(
        (failure) => Left(failure),
        (report) async {
          if (report.complianceStatus == ComplianceStatus.compliant) {
            return Right(DataRetentionResult(
              deletedItems: 0,
              retentionPeriod: report.retentionPeriod,
              enforcedAt: DateTime.now(),
            ));
          }
          
          int deletedCount = 0;
          
          // Delete old items
          for (final item in report.itemsToDelete) {
            switch (item.type) {
              case 'garment':
                await _database.delete(_database.garments)
                    .where((g) => g.id.equals(item.id))
                    .go();
                deletedCount++;
                break;
              case 'outfit':
                await _database.delete(_database.outfits)
                    .where((o) => o.id.equals(item.id))
                    .go();
                deletedCount++;
                break;
            }
          }
          
          // Log retention policy enforcement
          await _logPrivacyAction(
            PrivacyAction.dataRetentionEnforced,
            'Data retention policy enforced',
            {
              'deletedItems': deletedCount,
              'retentionPeriod': report.retentionPeriod.name,
              'timestamp': DateTime.now().toIso8601String(),
            },
          );
          
          return Right(DataRetentionResult(
            deletedItems: deletedCount,
            retentionPeriod: report.retentionPeriod,
            enforcedAt: DateTime.now(),
          ));
        },
      );
    } catch (e) {
      return Left(SecurityFailure('Failed to enforce data retention policy: $e'));
    }
  }
  
  /// Clear all privacy data
  Future<Either<Failure, void>> clearAllPrivacyData() async {
    try {
      // Clear privacy settings
      await _preferences.remove(_privacyPolicyAcceptedKey);
      await _preferences.remove(_dataCollectionConsentKey);
      await _preferences.remove(_analyticsConsentKey);
      await _preferences.remove(_marketingConsentKey);
      await _preferences.remove(_dataRetentionPeriodKey);
      await _preferences.remove(_lastPrivacyUpdateKey);
      
      // Clear audit log
      await _secureStorage.deleteSecureData(
        key: _privacyAuditLogKey,
        useSecureStorage: true,
      );
      
      // Clear export/deletion requests
      await _preferences.remove(_dataExportRequestKey);
      await _preferences.remove(_dataDeletionRequestKey);
      
      return const Right(null);
    } catch (e) {
      return Left(SecurityFailure('Failed to clear privacy data: $e'));
    }
  }
  
  // Private methods
  
  Future<void> _logPrivacyAction(
    PrivacyAction action,
    String description,
    Map<String, dynamic> metadata,
  ) async {
    try {
      final entry = PrivacyAuditEntry(
        id: _generateAuditId(),
        action: action,
        description: description,
        metadata: metadata,
        timestamp: DateTime.now(),
      );
      
      final logResult = await _secureStorage.getSecureString(
        key: _privacyAuditLogKey,
        useSecureStorage: true,
      );
      
      List<PrivacyAuditEntry> entries = [];
      
      logResult.fold(
        (failure) => entries = [],
        (logJson) {
          if (logJson != null) {
            final logData = json.decode(logJson) as List<dynamic>;
            entries = logData.map((e) => PrivacyAuditEntry.fromJson(e)).toList();
          }
        },
      );
      
      entries.add(entry);
      
      // Keep only last 1000 entries
      if (entries.length > 1000) {
        entries = entries.sublist(entries.length - 1000);
      }
      
      await _secureStorage.storeSecureString(
        key: _privacyAuditLogKey,
        value: json.encode(entries.map((e) => e.toJson()).toList()),
        useSecureStorage: true,
      );
    } catch (e) {
      // Log error but don't throw to avoid breaking main operations
      debugPrint('Failed to log privacy action: $e');
    }
  }
  
  Future<Map<String, dynamic>> _collectUserData(DataExportRequest request) async {
    final userData = <String, dynamic>{};
    
    if (request.includePersonalData) {
      // Collect user profile data
      userData['profile'] = {
        'preferences': _preferences.getKeys().where((key) => !key.startsWith('secure_')),
        'settings': getPrivacySettings().toJson(),
      };
    }
    
    // Collect app data
    final garments = await _database.select(_database.garments).get();
    userData['garments'] = garments.map((g) => g.toJson()).toList();
    
    final outfits = await _database.select(_database.outfits).get();
    userData['outfits'] = outfits.map((o) => o.toJson()).toList();
    
    if (request.includeAnalytics) {
      // Collect anonymized analytics data
      userData['analytics'] = {
        'usage_stats': {},
        'preferences': {},
      };
    }
    
    return userData;
  }
  
  Future<void> _storeExportRequest(DataExportRequest request, Map<String, dynamic> data) async {
    final requestData = {
      'request': request.toJson(),
      'data_size': json.encode(data).length,
      'timestamp': DateTime.now().toIso8601String(),
    };
    
    await _preferences.setString(_dataExportRequestKey, json.encode(requestData));
  }
  
  Future<void> _storeDeletionRequest(DataDeletionRequest request, Map<String, int> summary) async {
    final requestData = {
      'request': request.toJson(),
      'deletion_summary': summary,
      'timestamp': DateTime.now().toIso8601String(),
    };
    
    await _preferences.setString(_dataDeletionRequestKey, json.encode(requestData));
  }
  
  Future<Either<Failure, int>> _deletePersonalData() async {
    try {
      // Clear personal preferences
      final personalKeys = _preferences.getKeys().where((key) => 
        key.contains('personal') || key.contains('profile') || key.contains('user')
      ).toList();
      
      for (final key in personalKeys) {
        await _preferences.remove(key);
      }
      
      return Right(personalKeys.length);
    } catch (e) {
      return Left(SecurityFailure('Failed to delete personal data: $e'));
    }
  }
  
  Future<Either<Failure, int>> _deleteAppData() async {
    try {
      int deletedCount = 0;
      
      // Delete garments
      final garmentCount = await _database.select(_database.garments).get().then((g) => g.length);
      await _database.delete(_database.garments).go();
      deletedCount += garmentCount;
      
      // Delete outfits
      final outfitCount = await _database.select(_database.outfits).get().then((o) => o.length);
      await _database.delete(_database.outfits).go();
      deletedCount += outfitCount;
      
      return Right(deletedCount);
    } catch (e) {
      return Left(SecurityFailure('Failed to delete app data: $e'));
    }
  }
  
  Future<Either<Failure, int>> _deleteAnalyticsData() async {
    try {
      // Clear analytics preferences
      final analyticsKeys = _preferences.getKeys().where((key) => 
        key.contains('analytics') || key.contains('tracking') || key.contains('usage')
      ).toList();
      
      for (final key in analyticsKeys) {
        await _preferences.remove(key);
      }
      
      return Right(analyticsKeys.length);
    } catch (e) {
      return Left(SecurityFailure('Failed to delete analytics data: $e'));
    }
  }
  
  Duration _getRetentionDuration(DataRetentionPeriod period) {
    switch (period) {
      case DataRetentionPeriod.oneYear:
        return const Duration(days: 365);
      case DataRetentionPeriod.twoYears:
        return const Duration(days: 730);
      case DataRetentionPeriod.threeYears:
        return const Duration(days: 1095);
      case DataRetentionPeriod.indefinite:
        return const Duration(days: 36500); // 100 years
    }
  }
  
  String _generateAuditId() {
    final timestamp = DateTime.now().millisecondsSinceEpoch;
    return 'audit_$timestamp';
  }
  
  String _generateExportId() {
    final timestamp = DateTime.now().millisecondsSinceEpoch;
    return 'export_$timestamp';
  }
  
  String _generateDeletionId() {
    final timestamp = DateTime.now().millisecondsSinceEpoch;
    return 'deletion_$timestamp';
  }
}

/// Privacy settings
class PrivacySettings {
  final bool privacyPolicyAccepted;
  final bool dataCollectionConsent;
  final bool analyticsConsent;
  final bool marketingConsent;
  final DataRetentionPeriod dataRetentionPeriod;
  final DateTime? lastPrivacyUpdate;
  
  const PrivacySettings({
    required this.privacyPolicyAccepted,
    required this.dataCollectionConsent,
    required this.analyticsConsent,
    required this.marketingConsent,
    required this.dataRetentionPeriod,
    this.lastPrivacyUpdate,
  });
  
  Map<String, dynamic> toJson() => {
    'privacyPolicyAccepted': privacyPolicyAccepted,
    'dataCollectionConsent': dataCollectionConsent,
    'analyticsConsent': analyticsConsent,
    'marketingConsent': marketingConsent,
    'dataRetentionPeriod': dataRetentionPeriod.name,
    'lastPrivacyUpdate': lastPrivacyUpdate?.toIso8601String(),
  };
}

/// Data retention period options
enum DataRetentionPeriod {
  oneYear,
  twoYears,
  threeYears,
  indefinite,
}

/// Data export request
class DataExportRequest {
  final DataExportFormat format;
  final bool includePersonalData;
  final bool includeAnalytics;
  final bool includePurchaseHistory;
  
  const DataExportRequest({
    required this.format,
    required this.includePersonalData,
    required this.includeAnalytics,
    required this.includePurchaseHistory,
  });
  
  Map<String, dynamic> toJson() => {
    'format': format.name,
    'includePersonalData': includePersonalData,
    'includeAnalytics': includeAnalytics,
    'includePurchaseHistory': includePurchaseHistory,
  };
}

/// Data export format
enum DataExportFormat {
  json,
  csv,
  xml,
}

/// Data export result
class DataExportResult {
  final String exportId;
  final DataExportFormat format;
  final Map<String, dynamic> data;
  final int size;
  final DateTime createdAt;
  
  const DataExportResult({
    required this.exportId,
    required this.format,
    required this.data,
    required this.size,
    required this.createdAt,
  });
}

/// Data deletion request
class DataDeletionRequest {
  final bool deletePersonalData;
  final bool deleteAppData;
  final bool deleteAnalytics;
  final String reason;
  
  const DataDeletionRequest({
    required this.deletePersonalData,
    required this.deleteAppData,
    required this.deleteAnalytics,
    required this.reason,
  });
  
  Map<String, dynamic> toJson() => {
    'deletePersonalData': deletePersonalData,
    'deleteAppData': deleteAppData,
    'deleteAnalytics': deleteAnalytics,
    'reason': reason,
  };
}

/// Data deletion result
class DataDeletionResult {
  final String deletionId;
  final Map<String, int> deletedItems;
  final DateTime completedAt;
  
  const DataDeletionResult({
    required this.deletionId,
    required this.deletedItems,
    required this.completedAt,
  });
}

/// Privacy audit entry
class PrivacyAuditEntry {
  final String id;
  final PrivacyAction action;
  final String description;
  final Map<String, dynamic> metadata;
  final DateTime timestamp;
  
  const PrivacyAuditEntry({
    required this.id,
    required this.action,
    required this.description,
    required this.metadata,
    required this.timestamp,
  });
  
  Map<String, dynamic> toJson() => {
    'id': id,
    'action': action.name,
    'description': description,
    'metadata': metadata,
    'timestamp': timestamp.toIso8601String(),
  };
  
  factory PrivacyAuditEntry.fromJson(Map<String, dynamic> json) {
    return PrivacyAuditEntry(
      id: json['id'],
      action: PrivacyAction.values.firstWhere((a) => a.name == json['action']),
      description: json['description'],
      metadata: json['metadata'],
      timestamp: DateTime.parse(json['timestamp']),
    );
  }
}

/// Privacy actions for audit log
enum PrivacyAction {
  privacyPolicyAccepted,
  settingsUpdated,
  dataExportRequested,
  dataDeletionRequested,
  dataRetentionEnforced,
  consentWithdrawn,
  consentGranted,
}

/// Data retention report
class DataRetentionReport {
  final DataRetentionPeriod retentionPeriod;
  final DateTime cutoffDate;
  final List<RetentionItem> itemsToDelete;
  final ComplianceStatus complianceStatus;
  final DateTime checkDate;
  
  const DataRetentionReport({
    required this.retentionPeriod,
    required this.cutoffDate,
    required this.itemsToDelete,
    required this.complianceStatus,
    required this.checkDate,
  });
}

/// Retention item
class RetentionItem {
  final String id;
  final String type;
  final DateTime createdAt;
  final String description;
  
  const RetentionItem({
    required this.id,
    required this.type,
    required this.createdAt,
    required this.description,
  });
}

/// Data retention result
class DataRetentionResult {
  final int deletedItems;
  final DataRetentionPeriod retentionPeriod;
  final DateTime enforcedAt;
  
  const DataRetentionResult({
    required this.deletedItems,
    required this.retentionPeriod,
    required this.enforcedAt,
  });
}

/// Compliance status
enum ComplianceStatus {
  compliant,
  actionRequired,
  nonCompliant,
}